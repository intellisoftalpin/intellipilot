//! Per-project customer registry persistence.

use intellipilot_core::customer::Customer;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::DbError;

const COLS: &str = "id, project_id, name, company_name, contact_email, phone, notes, created_at";

fn row_to_customer(r: &Row) -> Customer {
    Customer {
        id: r.get("id"),
        project_id: r.get("project_id"),
        name: r.get("name"),
        company_name: r.get("company_name"),
        contact_email: r.get("contact_email"),
        phone: r.get("phone"),
        notes: r.get("notes"),
        created_at: r.get("created_at"),
    }
}

/// Writable customer fields (full-replace; the API merges patch over old).
#[derive(Debug, Default)]
pub struct CustomerWrite<'a> {
    pub name: &'a str,
    pub company_name: Option<&'a str>,
    pub contact_email: Option<&'a str>,
    pub phone: Option<&'a str>,
    pub notes: Option<&'a str>,
}

pub async fn list(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
) -> Result<Vec<Customer>, DbError> {
    let rows = client
        .query(
            &format!("SELECT {COLS} FROM customers WHERE project_id=$1 ORDER BY name"),
            &[&project_id],
        )
        .await?;
    Ok(rows.iter().map(row_to_customer).collect())
}

pub async fn get(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<Option<Customer>, DbError> {
    let row = client
        .query_opt(
            &format!("SELECT {COLS} FROM customers WHERE id=$1 AND project_id=$2"),
            &[&id, &project_id],
        )
        .await?;
    Ok(row.as_ref().map(row_to_customer))
}

pub async fn count(client: &deadpool_postgres::Client, project_id: Uuid) -> Result<i64, DbError> {
    let row = client
        .query_one(
            "SELECT count(*) AS n FROM customers WHERE project_id=$1",
            &[&project_id],
        )
        .await?;
    Ok(row.get("n"))
}

pub async fn create(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    created_by: Uuid,
    w: &CustomerWrite<'_>,
) -> Result<Customer, DbError> {
    let row = client
        .query_one(
            &format!(
                "INSERT INTO customers \
                   (project_id, name, company_name, contact_email, phone, notes, created_by) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING {COLS}"
            ),
            &[
                &project_id,
                &w.name,
                &w.company_name,
                &w.contact_email,
                &w.phone,
                &w.notes,
                &created_by,
            ],
        )
        .await?;
    Ok(row_to_customer(&row))
}

pub async fn update(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
    w: &CustomerWrite<'_>,
) -> Result<Option<Customer>, DbError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE customers SET name=$3, company_name=$4, contact_email=$5, phone=$6, \
                   notes=$7 WHERE id=$1 AND project_id=$2 RETURNING {COLS}"
            ),
            &[
                &id,
                &project_id,
                &w.name,
                &w.company_name,
                &w.contact_email,
                &w.phone,
                &w.notes,
            ],
        )
        .await?;
    Ok(row.as_ref().map(row_to_customer))
}

pub async fn delete(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let n = client
        .execute(
            "DELETE FROM customers WHERE id=$1 AND project_id=$2",
            &[&id, &project_id],
        )
        .await?;
    Ok(n > 0)
}

/// Whether a customer exists in this project (for issue.customer_id validation).
pub async fn in_project(
    client: &deadpool_postgres::Client,
    project_id: Uuid,
    id: Uuid,
) -> Result<bool, DbError> {
    let row = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM customers WHERE id=$1 AND project_id=$2) AS e",
            &[&id, &project_id],
        )
        .await?;
    Ok(row.get("e"))
}
