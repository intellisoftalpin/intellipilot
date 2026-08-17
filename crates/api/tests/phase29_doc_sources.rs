#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::let_underscore_untyped
)]
//! Phase 29 acceptance: external documentation sources.
//!
//! The security-critical surface is the **path jail**: nothing above a
//! source's `doc_path` may ever be listed, read, or written, and a link that
//! climbs out must be refused rather than clamped. Those cases are asserted
//! against a real bare repository seeded with content on both sides of the
//! jail boundary.
//!
//! Registration itself talks to a git remote, so tests here drive the read and
//! write paths against a pre-seeded cache and cover registration through its
//! validation and permission behaviour.

mod common;

use std::path::Path;

use common::{TestApp, delete_bearer, get_with_bearer, post_json_bearer, req};
use serde_json::{Value, json};
use uuid::Uuid;

const STRONG_PW: &str = "7xK!pq2$mz9Wbe#aQ";
const MODE_BLOB: i32 = 0o100_644;
const MODE_TREE: i32 = 0o040_000;
const MODE_SYMLINK: i32 = 0o120_000;

async fn fresh_user(app: &TestApp, email: &str, username: &str) -> String {
    let _ = app.register(email, username, STRONG_PW).await;
    app.login(email, STRONG_PW)
        .await
        .access_token()
        .expect("access token")
}

async fn owner_project(app: &TestApp) -> (String, String) {
    let token = fresh_user(app, "docs@example.com", "docsuser").await;
    let p = app
        .send(post_json_bearer(
            "/api/v1/projects",
            &token,
            &json!({ "name": "Docs" }),
        ))
        .await;
    assert_eq!(p.status, 201, "{:?}", p.json);
    (token, p.json["id"].as_str().unwrap().to_owned())
}

/// Create a role with exactly `permissions` and return a member holding it.
async fn member_with_role(
    app: &TestApp,
    owner: &str,
    pid: &str,
    slug: &str,
    permissions: &[&str],
    email: &str,
    username: &str,
) -> String {
    let role = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/roles"),
            owner,
            &json!({ "name": slug, "slug": slug, "permissions": permissions }),
        ))
        .await;
    assert_eq!(role.status, 201, "create role: {:?}", role.json);
    let invite = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/invitations"),
            owner,
            &json!({ "email": email, "role": slug }),
        ))
        .await;
    let itoken = invite.json["invite_token"].as_str().unwrap().to_owned();
    let member = fresh_user(app, email, username).await;
    let accept = app
        .send(post_json_bearer(
            "/api/v1/invitations/accept",
            &member,
            &json!({ "token": itoken }),
        ))
        .await;
    assert!(
        accept.status == 200 || accept.status == 204,
        "accept invite: {:?}",
        accept.json
    );
    member
}

/// Seed a bare repository laid out so that the jail boundary is testable:
///
/// ```text
/// docs/README.md         inside  — the homepage
/// docs/guides/intro.md   inside  — one level down
/// docs/img/logo.png      inside  — an image
/// docs/img/chart.svg     inside  — an SVG carrying a <script>
/// docs/notes.bin         inside  — not a document
/// docs/escape.md         inside  — a SYMLINK naming a file above the jail
/// SECRET.md              OUTSIDE — must never be reachable
/// ```
fn seed_repo(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let repo = git2::Repository::init_bare(dir).unwrap();
    let sig = git2::Signature::now("Docs Bot", "bot@example.com").unwrap();

    let root = {
        let b = |c: &[u8]| repo.blob(c).unwrap();
        let subtree = |entries: &[(&str, git2::Oid, i32)]| {
            let mut t = repo.treebuilder(None).unwrap();
            for (name, oid, mode) in entries {
                t.insert(*name, *oid, *mode).unwrap();
            }
            t.write().unwrap()
        };
        let guides = subtree(&[(
            "intro.md",
            b(b"# Intro\n\n| a | b |\n|---|---|\n"),
            MODE_BLOB,
        )]);
        let img = subtree(&[
            ("logo.png", b(b"\x89PNG\r\n\x1a\nfake"), MODE_BLOB),
            (
                "chart.svg",
                b(b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script><rect/></svg>"),
                MODE_BLOB,
            ),
        ]);
        let docs = subtree(&[
            ("README.md", b(b"# Handbook\n\nWelcome.\n"), MODE_BLOB),
            ("guides", guides, MODE_TREE),
            ("img", img, MODE_TREE),
            ("notes.bin", b(b"\x00\x01binary"), MODE_BLOB),
            ("escape.md", b(b"../SECRET.md"), MODE_SYMLINK),
        ]);
        subtree(&[
            ("docs", docs, MODE_TREE),
            ("SECRET.md", b(b"# Do not show\n"), MODE_BLOB),
        ])
    };

    let tree = repo.find_tree(root).unwrap();
    repo.commit(Some("refs/heads/main"), &sig, &sig, "seed", &tree, &[])
        .unwrap()
        .to_string()
}

/// Register a source directly in the database and seed its cache, bypassing
/// the network round-trip that real registration performs.
async fn seeded_source(app: &TestApp, pid: &str, read_only: bool) -> String {
    let project_id = Uuid::parse_str(pid).unwrap();
    let source_id = Uuid::now_v7();
    let head = seed_repo(&app.docs.dir_for(project_id, source_id));

    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO doc_sources \
               (id, project_id, name, kind, ssh_url, web_url, branch, doc_path, \
                read_only, cache_status, head_commit) \
             VALUES ($1,$2,'Handbook','git','git@example.com:acme/docs.git', \
                     'https://example.com/acme/docs','main','docs',$3,'ready',$4)",
            &[&source_id, &project_id, &read_only, &head],
        )
        .await
        .unwrap();
    source_id.to_string()
}

/// A source registered but never synced — nothing in its cache yet.
async fn unsynced_source(app: &TestApp, pid: &str) -> String {
    let project_id = Uuid::parse_str(pid).unwrap();
    let source_id = Uuid::now_v7();
    let client = app.db.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO doc_sources \
               (id, project_id, name, kind, ssh_url, web_url, branch, doc_path, \
                cache_status) \
             VALUES ($1,$2,'Pending','git','git@example.com:acme/p.git', \
                     'https://example.com/acme/p','main','','pending')",
            &[&source_id, &project_id],
        )
        .await
        .unwrap();
    source_id.to_string()
}

fn tree_paths(v: &Value) -> Vec<String> {
    fn walk(entries: &[Value], out: &mut Vec<String>) {
        for e in entries {
            out.push(e["path"].as_str().unwrap().to_owned());
            if let Some(children) = e["children"].as_array() {
                walk(children, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(v["entries"].as_array().unwrap(), &mut out);
    out
}

// --- registration ---------------------------------------------------------

#[tokio::test]
async fn creating_a_source_validates_url_branch_and_path() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let url = format!("/api/v1/projects/{pid}/doc-sources");

    // An HTTP(S) URL can never authenticate with a deploy key.
    let http = app
        .send(post_json_bearer(
            &url,
            &owner,
            &json!({
                "name": "D", "ssh_url": "https://github.com/acme/docs.git",
                "web_url": "https://github.com/acme/docs", "branch": "main"
            }),
        ))
        .await;
    assert_eq!(http.status, 422, "{:?}", http.json);

    // The web URL is rendered as a link, so it must be http(s).
    let web = app
        .send(post_json_bearer(
            &url,
            &owner,
            &json!({
                "name": "D", "ssh_url": "git@github.com:acme/docs.git",
                "web_url": "javascript:alert(1)", "branch": "main"
            }),
        ))
        .await;
    assert_eq!(web.status, 422, "{:?}", web.json);

    // A jail that climbs out of the repository is a configuration error.
    let path = app
        .send(post_json_bearer(
            &url,
            &owner,
            &json!({
                "name": "D", "ssh_url": "git@github.com:acme/docs.git",
                "web_url": "https://github.com/acme/docs", "branch": "main",
                "doc_path": "../../etc"
            }),
        ))
        .await;
    assert_eq!(path.status, 422, "{:?}", path.json);

    // A branch name that would break out of the refspec.
    let branch = app
        .send(post_json_bearer(
            &url,
            &owner,
            &json!({
                "name": "D", "ssh_url": "git@github.com:acme/docs.git",
                "web_url": "https://github.com/acme/docs",
                "branch": "main:refs/heads/evil"
            }),
        ))
        .await;
    assert_eq!(branch.status, 422, "{:?}", branch.json);
}

#[tokio::test]
async fn browsing_requires_the_view_permission() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    // A role that can see the project but holds no doc_source permission.
    let outsider = member_with_role(
        &app,
        &owner,
        &pid,
        "nodocs",
        &["project.view", "issue.view"],
        "nodocs@example.com",
        "nodocs",
    )
    .await;

    for path in [
        format!("/api/v1/projects/{pid}/doc-sources"),
        format!("/api/v1/projects/{pid}/doc-sources/{sid}/tree"),
        format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=README.md"),
    ] {
        let r = app.send(get_with_bearer(&path, &outsider)).await;
        assert_eq!(r.status, 403, "{path} should be forbidden: {:?}", r.json);
    }
}

#[tokio::test]
async fn sources_are_capped_at_ten_per_project() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let project_id = Uuid::parse_str(&pid).unwrap();

    let client = app.db.pool.get().await.unwrap();
    for i in 0..10 {
        client
            .execute(
                "INSERT INTO doc_sources \
                   (project_id, name, kind, ssh_url, web_url, branch, doc_path) \
                 VALUES ($1,$2,'git','git@example.com:a/b.git', \
                         'https://example.com/a/b','main','')",
                &[&project_id, &format!("src-{i}")],
            )
            .await
            .unwrap();
    }
    drop(client);

    let over = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "eleventh", "ssh_url": "git@github.com:acme/docs.git",
                "web_url": "https://github.com/acme/docs", "branch": "main"
            }),
        ))
        .await;
    assert_eq!(over.status, 409, "{:?}", over.json);
    assert_eq!(over.json["code"], "limit_reached");
}

#[tokio::test]
async fn updating_a_source_requires_if_match() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;
    let url = format!("/api/v1/projects/{pid}/doc-sources/{sid}");

    let bare = app
        .send(req(
            "PATCH",
            &url,
            Some(&owner),
            &[],
            Some(&json!({ "name": "Renamed" })),
        ))
        .await;
    assert_eq!(bare.status, 428, "{:?}", bare.json);

    let stale = app
        .send(req(
            "PATCH",
            &url,
            Some(&owner),
            &[("if-match", &format!("\"{sid}:99\""))],
            Some(&json!({ "name": "Renamed" })),
        ))
        .await;
    assert_eq!(stale.status, 412, "{:?}", stale.json);

    let current = app.send(get_with_bearer(&url, &owner)).await;
    let etag = current.header("etag").unwrap().to_owned();
    let ok = app
        .send(req(
            "PATCH",
            &url,
            Some(&owner),
            &[("if-match", &etag)],
            Some(&json!({ "name": "Renamed", "emoji": "📘" })),
        ))
        .await;
    assert_eq!(ok.status, 200, "{:?}", ok.json);
    assert_eq!(ok.json["name"], "Renamed");
    assert_eq!(ok.json["emoji"], "📘");
    assert_eq!(ok.json["version"], 2);
}

// --- the path jail --------------------------------------------------------

#[tokio::test]
async fn the_tree_lists_only_documents_inside_the_jail() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/tree"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);

    let paths = tree_paths(&r.json);
    // Documents inside the jail, addressed relative to it — the repository
    // layout above `docs/` is not even implied by the paths we hand out.
    assert!(paths.contains(&"README.md".to_owned()));
    assert!(paths.contains(&"guides".to_owned()));
    assert!(paths.contains(&"guides/intro.md".to_owned()));
    // Non-documents are invisible, as is a directory holding only those.
    assert!(!paths.contains(&"notes.bin".to_owned()));
    assert!(!paths.contains(&"img".to_owned()));
    // Nothing above the jail, and the symlink that names it is not listed.
    assert!(!paths.iter().any(|p| p.contains("SECRET")));
    assert!(!paths.contains(&"escape.md".to_owned()));

    // README is picked as the homepage.
    assert_eq!(r.json["entry_path"], "README.md");
    assert_eq!(r.json["commit"].as_str().unwrap().len(), 40);
}

/// The central security assertion: a path that climbs above the jail is
/// **refused**, not clamped back inside. Clamping would silently serve a
/// different file; refusing cannot.
#[tokio::test]
async fn paths_climbing_above_the_jail_are_refused() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    for attack in [
        "../SECRET.md",
        "../../SECRET.md",
        "guides/../../SECRET.md",
        "..%2FSECRET.md",
        "a/b/../../../SECRET.md",
    ] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path={attack}"),
                &owner,
            ))
            .await;
        assert!(
            r.status == 422 || r.status == 404,
            "{attack} leaked with {}: {:?}",
            r.status,
            r.json
        );
        let body = serde_json::to_string(&r.json).unwrap();
        assert!(
            !body.contains("Do not show"),
            "{attack} returned content from above the jail"
        );
    }
}

/// A symlink is a second way to name something outside the repository's own
/// tree. It is skipped rather than dereferenced.
#[tokio::test]
async fn symlinks_are_not_followed() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=escape.md"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 404, "{:?}", r.json);
}

#[tokio::test]
async fn a_document_comes_back_as_markdown_with_an_etag() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let r = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=README.md"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    // The raw source, not HTML: the client renders it, which is what keeps
    // link resolution (and therefore the jail) on the client side.
    assert_eq!(r.json["body"], "# Handbook\n\nWelcome.\n");
    assert_eq!(r.json["path"], "README.md");
    assert_eq!(r.json["blob_oid"].as_str().unwrap().len(), 40);
    // The ETag is the blob OID, which is what a save must present.
    let etag = r.header("etag").unwrap();
    assert_eq!(
        etag,
        format!("\"{}\"", r.json["blob_oid"].as_str().unwrap())
    );
    // Authorship comes straight from git.
    assert_eq!(r.json["last_commit"]["author_name"], "Docs Bot");
    assert_eq!(r.json["last_commit"]["message"], "seed");
    // No write key configured, so not editable.
    assert_eq!(r.json["can_edit"], false);
}

#[tokio::test]
async fn only_documents_are_readable_as_documents() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    for path in ["notes.bin", "img/logo.png", "guides"] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path={path}"),
                &owner,
            ))
            .await;
        assert_eq!(r.status, 404, "{path} should not read as a document");
    }
}

#[tokio::test]
async fn images_are_served_and_other_files_are_not() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let (status, headers, bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/blob?path=img/logo.png"),
            &owner,
        ))
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("content-type").unwrap(), "image/png");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert!(bytes.starts_with(b"\x89PNG"));

    // A non-image is not servable through the blob endpoint, whatever it is.
    let (bin_status, _, _) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/blob?path=notes.bin"),
            &owner,
        ))
        .await;
    assert_eq!(bin_status, 404);

    // Nor is anything above the jail.
    let (escape_status, _, escape_bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/blob?path=../SECRET.md"),
            &owner,
        ))
        .await;
    assert!(escape_status == 422 || escape_status == 404);
    assert!(!escape_bytes.windows(11).any(|w| w == b"Do not show"));
}

/// SVG is the one image format that can carry script, so it is sanitized
/// before it leaves the server rather than trusted to the renderer.
#[tokio::test]
async fn svg_images_are_sanitized() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let (status, headers, bytes) = app
        .download_bytes(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/blob?path=img/chart.svg"),
            &owner,
        ))
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("content-type").unwrap(), "image/svg+xml");
    let body = String::from_utf8_lossy(&bytes).to_lowercase();
    assert!(!body.contains("<script"), "script survived: {body}");
    assert!(!body.contains("alert(1)"), "payload survived: {body}");
}

#[tokio::test]
async fn an_unsynced_source_reports_that_it_is_not_ready() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = unsynced_source(&app, &pid).await;

    for suffix in ["tree", "doc?path=README.md"] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}/doc-sources/{sid}/{suffix}"),
                &owner,
            ))
            .await;
        // Retryable, not "missing": the document may well exist.
        assert_eq!(r.status, 503, "{suffix}: {:?}", r.json);
        assert_eq!(r.json["code"], "doc_source_not_ready");
    }
}

// --- editing --------------------------------------------------------------

#[tokio::test]
async fn saving_needs_a_personal_write_key() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let r = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=README.md"),
            Some(&owner),
            &[("if-match", "\"deadbeef\"")],
            Some(&json!({ "content": "# Changed\n" })),
        ))
        .await;
    assert_eq!(r.status, 409, "{:?}", r.json);
    assert_eq!(r.json["code"], "doc_write_key_missing");
}

#[tokio::test]
async fn a_read_only_source_refuses_saves_outright() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, true).await;

    // Even with a key registered, the source's own flag wins.
    let key = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-keys/me"),
            Some(&owner),
            &[],
            Some(&json!({})),
        ))
        .await;
    assert_eq!(key.status, 200, "{:?}", key.json);

    let r = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=README.md"),
            Some(&owner),
            &[("if-match", "\"deadbeef\"")],
            Some(&json!({ "content": "# Changed\n" })),
        ))
        .await;
    assert_eq!(r.status, 409, "{:?}", r.json);
    assert_eq!(r.json["code"], "doc_source_read_only");
}

#[tokio::test]
async fn saving_requires_if_match() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    // A write key first: preconditions are only evaluated once the request
    // would otherwise succeed (RFC 9110 §13.2), so without one the capability
    // failure is reported instead.
    let key = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-keys/me"),
            Some(&owner),
            &[],
            Some(&json!({})),
        ))
        .await;
    assert_eq!(key.status, 200, "{:?}", key.json);

    let r = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=README.md"),
            Some(&owner),
            &[],
            Some(&json!({ "content": "# Changed\n" })),
        ))
        .await;
    assert_eq!(r.status, 428, "{:?}", r.json);
}

#[tokio::test]
async fn saving_outside_the_jail_is_refused() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    let r = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=../SECRET.md"),
            Some(&owner),
            &[("if-match", "\"deadbeef\"")],
            Some(&json!({ "content": "owned\n" })),
        ))
        .await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "doc_path_escapes");
}

// --- personal write keys --------------------------------------------------

#[tokio::test]
async fn a_generated_write_key_exposes_only_its_public_half() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let url = format!("/api/v1/projects/{pid}/doc-keys/me");

    let created = app
        .send(req("PUT", &url, Some(&owner), &[], Some(&json!({}))))
        .await;
    assert_eq!(created.status, 200, "{:?}", created.json);
    assert_eq!(created.json["origin"], "generated");
    let public = created.json["public_key"].as_str().unwrap();
    assert!(public.starts_with("ssh-ed25519 "));
    assert!(
        created.json["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );

    // The private half must not be reachable through any projection.
    let body = serde_json::to_string(&created.json).unwrap();
    assert!(!body.contains("PRIVATE KEY"), "private key leaked: {body}");
    assert!(!body.contains("private_key"), "private key leaked: {body}");

    let fetched = app.send(get_with_bearer(&url, &owner)).await;
    assert_eq!(fetched.status, 200);
    assert_eq!(fetched.json["public_key"], public);
    let fetched_body = serde_json::to_string(&fetched.json).unwrap();
    assert!(!fetched_body.contains("PRIVATE KEY"));

    // Re-registering rotates rather than erroring — one key per user.
    let rotated = app
        .send(req("PUT", &url, Some(&owner), &[], Some(&json!({}))))
        .await;
    assert_eq!(rotated.status, 200);
    assert_ne!(rotated.json["public_key"], public);

    let removed = app.send(delete_bearer(&url, &owner)).await;
    assert_eq!(removed.status, 204);
    let gone = app.send(get_with_bearer(&url, &owner)).await;
    assert_eq!(gone.status, 200);
    assert!(gone.json["doc_key"].is_null());
}

#[tokio::test]
async fn importing_a_key_validates_it() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let url = format!("/api/v1/projects/{pid}/doc-keys/me");

    let junk = app
        .send(req(
            "PUT",
            &url,
            Some(&owner),
            &[],
            Some(&json!({ "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n" })),
        ))
        .await;
    assert_eq!(junk.status, 422, "{:?}", junk.json);
    assert_eq!(junk.json["code"], "invalid_private_key");
}

#[tokio::test]
async fn having_a_write_key_makes_a_document_editable() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;
    let doc = format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=README.md");

    let before = app.send(get_with_bearer(&doc, &owner)).await;
    assert_eq!(before.json["can_edit"], false);

    let key = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-keys/me"),
            Some(&owner),
            &[],
            Some(&json!({})),
        ))
        .await;
    assert_eq!(key.status, 200, "{:?}", key.json);

    let after = app.send(get_with_bearer(&doc, &owner)).await;
    assert_eq!(after.json["can_edit"], true);
}

// --- the internal wiki toggle ---------------------------------------------

/// Disabling the internal wiki hides it without deleting anything, and reads
/// as 404 rather than 403 so a bookmark cannot confirm that content is still
/// there.
#[tokio::test]
async fn disabling_the_internal_wiki_hides_it_reversibly() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;

    let page = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &owner,
            &json!({ "title": "Onboarding", "body": "# Hello" }),
        ))
        .await;
    assert_eq!(page.status, 201, "{:?}", page.json);
    let page_id = page.json["id"].as_str().unwrap().to_owned();

    let off = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}"),
            Some(&owner),
            &[],
            Some(&json!({ "wiki_enabled": false })),
        ))
        .await;
    assert_eq!(off.status, 200, "{:?}", off.json);
    assert_eq!(off.json["wiki_enabled"], false);

    for path in [
        format!("/api/v1/projects/{pid}/wiki"),
        format!("/api/v1/projects/{pid}/wiki/{page_id}"),
        format!("/api/v1/projects/{pid}/wiki/{page_id}/revisions"),
    ] {
        let r = app.send(get_with_bearer(&path, &owner)).await;
        assert_eq!(r.status, 404, "{path} should read as absent: {:?}", r.json);
    }
    // Writes are closed too, not just reads.
    let write = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/wiki"),
            &owner,
            &json!({ "title": "Sneaky", "body": "x" }),
        ))
        .await;
    assert_eq!(write.status, 404, "{:?}", write.json);

    // Re-enabling brings the page back untouched — nothing was deleted.
    let on = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}"),
            Some(&owner),
            &[],
            Some(&json!({ "wiki_enabled": true })),
        ))
        .await;
    assert_eq!(on.status, 200, "{:?}", on.json);

    let back = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/wiki/{page_id}"),
            &owner,
        ))
        .await;
    assert_eq!(back.status, 200, "{:?}", back.json);
    assert_eq!(back.json["title"], "Onboarding");
    assert_eq!(back.json["body"], "# Hello");
    assert_eq!(back.json["version"], 1);
}

// --- deletion -------------------------------------------------------------

#[tokio::test]
async fn deleting_a_source_removes_its_cache() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;
    let dir = app.docs.dir_for(
        Uuid::parse_str(&pid).unwrap(),
        Uuid::parse_str(&sid).unwrap(),
    );
    assert!(dir.exists(), "cache should have been seeded");

    let r = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}"),
            &owner,
        ))
        .await;
    assert_eq!(r.status, 204, "{:?}", r.json);
    assert!(!dir.exists(), "cache directory should have been reclaimed");

    let gone = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}"),
            &owner,
        ))
        .await;
    assert_eq!(gone.status, 404);
}

#[tokio::test]
async fn a_developer_can_edit_but_not_register_sources() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;

    // The default developer set: read and edit documents, but registering or
    // removing a whole source is admin-level.
    let dev = member_with_role(
        &app,
        &owner,
        &pid,
        "docdev",
        &["project.view", "doc_source.view", "doc_source.modify"],
        "docdev@example.com",
        "docdev",
    )
    .await;

    let read = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/tree"),
            &dev,
        ))
        .await;
    assert_eq!(read.status, 200, "{:?}", read.json);

    let create = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &dev,
            &json!({
                "name": "New", "ssh_url": "git@github.com:acme/d.git",
                "web_url": "https://github.com/acme/d", "branch": "main"
            }),
        ))
        .await;
    assert_eq!(create.status, 403, "{:?}", create.json);

    let remove = app
        .send(delete_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}"),
            &dev,
        ))
        .await;
    assert_eq!(remove.status, 403, "{:?}", remove.json);
}

// --- web-link sources -----------------------------------------------------

/// A web source needs only a name and a URL — no key, no branch, no remote to
/// probe — so unlike a git source it can be registered end-to-end in a test.
#[tokio::test]
async fn a_web_source_needs_only_a_name_and_a_url() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;

    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "Status page",
                "kind": "web",
                "web_url": "https://status.example.com/handbook"
            }),
        ))
        .await;
    assert_eq!(created.status, 201, "{:?}", created.json);
    assert_eq!(created.json["kind"], "web");
    assert_eq!(created.json["name"], "Status page");
    // The URL is stored verbatim: it IS the page, so trimming a trailing
    // component could change which page opens.
    assert_eq!(
        created.json["web_url"],
        "https://status.example.com/handbook"
    );
    // Read-only by construction — there is nowhere to push to.
    assert_eq!(created.json["read_only"], true);
    assert_eq!(created.json["hidden"], false);
    // Nothing repository-shaped comes back.
    assert!(created.json.get("ssh_url").is_none());
    assert!(created.json.get("branch").is_none());
    assert_eq!(created.json["doc_path"], "");
}

/// The two kinds have disjoint field sets. A request mixing them is a mistake,
/// and dropping the stray fields would register something else.
#[tokio::test]
async fn a_web_source_refuses_repository_fields() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let url = format!("/api/v1/projects/{pid}/doc-sources");

    for extra in [
        json!({ "ssh_url": "git@github.com:acme/docs.git" }),
        json!({ "branch": "main" }),
        json!({ "doc_path": "docs" }),
        json!({ "new_key": { "name": "k" } }),
    ] {
        let mut body = json!({
            "name": "Web",
            "kind": "web",
            "web_url": "https://example.com/docs"
        });
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let r = app.send(post_json_bearer(&url, &owner, &body)).await;
        assert_eq!(r.status, 422, "{extra} should be refused: {:?}", r.json);
        assert_eq!(r.json["code"], "web_source_fields");
    }
}

/// A git source still requires what it always did, now that the fields are
/// optional on the wire.
#[tokio::test]
async fn a_git_source_still_requires_a_url_and_branch() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let url = format!("/api/v1/projects/{pid}/doc-sources");

    let no_ssh = app
        .send(post_json_bearer(
            &url,
            &owner,
            &json!({
                "name": "G", "kind": "git",
                "web_url": "https://github.com/acme/docs", "branch": "main"
            }),
        ))
        .await;
    assert_eq!(no_ssh.status, 422, "{:?}", no_ssh.json);
    assert_eq!(no_ssh.json["code"], "ssh_url_required");

    let no_branch = app
        .send(post_json_bearer(
            &url,
            &owner,
            &json!({
                "name": "G", "kind": "git",
                "ssh_url": "git@github.com:acme/docs.git",
                "web_url": "https://github.com/acme/docs"
            }),
        ))
        .await;
    assert_eq!(no_branch.status, 422, "{:?}", no_branch.json);
    assert_eq!(no_branch.json["code"], "branch_required");
}

/// A client written before web links existed sends no `kind` at all.
#[tokio::test]
async fn an_omitted_kind_still_means_git() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    // No key and no reachable remote, so this gets as far as the git path and
    // fails there — which is itself the proof that it was treated as git.
    let r = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "G",
                "ssh_url": "git@github.com:acme/docs.git",
                "web_url": "https://github.com/acme/docs",
                "branch": "main"
            }),
        ))
        .await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "ssh_key_required");
}

/// Nothing is served for a web link: the browser fetches the page directly.
#[tokio::test]
async fn a_web_source_serves_no_content_endpoints() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "Web", "kind": "web",
                "web_url": "https://example.com/docs"
            }),
        ))
        .await;
    let sid = created.json["id"].as_str().unwrap().to_owned();

    for suffix in ["tree", "doc?path=README.md", "blob?path=a.png"] {
        let r = app
            .send(get_with_bearer(
                &format!("/api/v1/projects/{pid}/doc-sources/{sid}/{suffix}"),
                &owner,
            ))
            .await;
        assert_eq!(r.status, 422, "{suffix}: {:?}", r.json);
        assert_eq!(r.json["code"], "doc_source_is_web");
    }
}

/// Editing is impossible for a web link by design, and the flag cannot be
/// cleared to make it possible.
#[tokio::test]
async fn a_web_source_can_never_become_editable() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "Web", "kind": "web",
                "web_url": "https://example.com/docs"
            }),
        ))
        .await;
    let sid = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();

    let unlock = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}"),
            Some(&owner),
            &[("if-match", &etag)],
            Some(&json!({ "read_only": false })),
        ))
        .await;
    assert_eq!(unlock.status, 422, "{:?}", unlock.json);
    assert_eq!(unlock.json["code"], "web_source_read_only");

    let save = app
        .send(req(
            "PUT",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}/doc?path=a.md"),
            Some(&owner),
            &[("if-match", "\"x\"")],
            Some(&json!({ "content": "# Nope\n" })),
        ))
        .await;
    assert_eq!(save.status, 422, "{:?}", save.json);
    assert_eq!(save.json["code"], "doc_source_is_web");
}

/// A web link has no branch, folder or key to reconfigure.
#[tokio::test]
async fn a_web_source_refuses_repository_patches() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "Web", "kind": "web",
                "web_url": "https://example.com/docs"
            }),
        ))
        .await;
    let sid = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();

    let r = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}"),
            Some(&owner),
            &[("if-match", &etag)],
            Some(&json!({ "branch": "main" })),
        ))
        .await;
    assert_eq!(r.status, 422, "{:?}", r.json);
    assert_eq!(r.json["code"], "web_source_fields");
}

/// Renaming is how a web link gets its human title, so it must work.
#[tokio::test]
async fn a_web_source_can_be_retitled_and_restyled() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let created = app
        .send(post_json_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &owner,
            &json!({
                "name": "Raw title", "kind": "web",
                "web_url": "https://example.com/docs"
            }),
        ))
        .await;
    let sid = created.json["id"].as_str().unwrap().to_owned();
    let etag = created.header("etag").unwrap().to_owned();

    let r = app
        .send(req(
            "PATCH",
            &format!("/api/v1/projects/{pid}/doc-sources/{sid}"),
            Some(&owner),
            &[("if-match", &etag)],
            Some(&json!({
                "name": "Company handbook",
                "web_url": "https://example.com/handbook",
                "emoji": "🌐",
                "color": "#3F8CFF"
            })),
        ))
        .await;
    assert_eq!(r.status, 200, "{:?}", r.json);
    assert_eq!(r.json["name"], "Company handbook");
    assert_eq!(r.json["web_url"], "https://example.com/handbook");
    assert_eq!(r.json["emoji"], "🌐");
    assert_eq!(r.json["kind"], "web");
}

// --- the hide switch ------------------------------------------------------

/// Hiding withdraws a source from navigation without discarding anything.
/// Readers cannot see or reach it; managers still can, so they can check it
/// before putting it back.
#[tokio::test]
async fn hiding_a_source_withdraws_it_reversibly() {
    require_db!();
    let app = TestApp::spawn().await;
    let (owner, pid) = owner_project(&app).await;
    let sid = seeded_source(&app, &pid, false).await;
    let source_url = format!("/api/v1/projects/{pid}/doc-sources/{sid}");

    let reader = member_with_role(
        &app,
        &owner,
        &pid,
        "docreader",
        &["project.view", "doc_source.view"],
        "docreader@example.com",
        "docreader",
    )
    .await;

    // Visible to the reader while live.
    let before = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &reader,
        ))
        .await;
    assert_eq!(before.json["doc_sources"].as_array().unwrap().len(), 1);

    let current = app.send(get_with_bearer(&source_url, &owner)).await;
    let etag = current.header("etag").unwrap().to_owned();
    let hide = app
        .send(req(
            "PATCH",
            &source_url,
            Some(&owner),
            &[("if-match", &etag)],
            Some(&json!({ "hidden": true })),
        ))
        .await;
    assert_eq!(hide.status, 200, "{:?}", hide.json);
    assert_eq!(hide.json["hidden"], true);

    // Gone from the reader's listing, and their bookmarks read as absent —
    // 404, not 403, so the switch itself is not disclosed.
    let after = app
        .send(get_with_bearer(
            &format!("/api/v1/projects/{pid}/doc-sources"),
            &reader,
        ))
        .await;
    assert!(after.json["doc_sources"].as_array().unwrap().is_empty());
    for suffix in ["", "/tree", "/doc?path=README.md"] {
        let r = app
            .send(get_with_bearer(&format!("{source_url}{suffix}"), &reader))
            .await;
        assert_eq!(
            r.status, 404,
            "{suffix} should read as absent: {:?}",
            r.json
        );
    }

    // The manager still reaches it, and the configuration is untouched.
    let managed = app.send(get_with_bearer(&source_url, &owner)).await;
    assert_eq!(managed.status, 200);
    assert_eq!(managed.json["doc_path"], "docs");
    assert_eq!(managed.json["branch"], "main");
    let still_readable = app
        .send(get_with_bearer(&format!("{source_url}/tree"), &owner))
        .await;
    assert_eq!(still_readable.status, 200, "{:?}", still_readable.json);

    // Unhiding restores it for the reader exactly as it was.
    let etag2 = managed.header("etag").unwrap().to_owned();
    let show = app
        .send(req(
            "PATCH",
            &source_url,
            Some(&owner),
            &[("if-match", &etag2)],
            Some(&json!({ "hidden": false })),
        ))
        .await;
    assert_eq!(show.status, 200, "{:?}", show.json);
    let restored = app
        .send(get_with_bearer(&format!("{source_url}/tree"), &reader))
        .await;
    assert_eq!(restored.status, 200, "{:?}", restored.json);
    assert_eq!(restored.json["entry_path"], "README.md");
}
