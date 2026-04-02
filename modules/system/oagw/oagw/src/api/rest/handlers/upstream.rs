use axum::Json;
use axum::extract::{Extension, Path, Query};
use axum::response::IntoResponse;
use http::StatusCode;
use modkit::api::problem::Problem;
use modkit_security::SecurityContext;

use crate::api::rest::dto::{CreateUpstreamRequest, UpdateUpstreamRequest, UpstreamResponse};
use crate::api::rest::error::domain_error_to_problem;
use crate::api::rest::extractors::{PaginationQuery, parse_gts_id};
use crate::domain::gts_helpers as gts;
use crate::domain::model::Upstream;
use crate::module::AppState;
use crate::request_instance::RequestInstance;

fn to_response(u: Upstream) -> UpstreamResponse {
    UpstreamResponse {
        id: gts::format_upstream_gts(u.id),
        tenant_id: u.tenant_id,
        alias: u.alias,
        server: u.server.into(),
        protocol: u.protocol,
        enabled: u.enabled,
        auth: u.auth.map(Into::into),
        headers: u.headers.map(Into::into),
        plugins: u.plugins.map(Into::into),
        rate_limit: u.rate_limit.map(Into::into),
        cors: u.cors.map(Into::into),
        tags: u.tags,
    }
}

pub async fn create_upstream(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    request_instance: RequestInstance,
    Json(req): Json<CreateUpstreamRequest>,
) -> Result<impl IntoResponse, Problem> {
    let upstream = state
        .cp
        .create_upstream(&ctx, req.into())
        .await
        .map_err(|e| domain_error_to_problem(e, request_instance))?;
    // Defensive no-op: new IDs have no cache entry, but keeps CRUD handlers uniform.
    state.backend_selector.invalidate(upstream.id);
    Ok((StatusCode::CREATED, Json(to_response(upstream))))
}

pub async fn get_upstream(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    request_instance: RequestInstance,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    let uuid = match parse_gts_id(&id, gts::UPSTREAM_SCHEMA) {
        Ok(uuid) => uuid,
        Err(e) => return Err(domain_error_to_problem(e, request_instance)),
    };
    let upstream = state
        .cp
        .get_upstream(&ctx, uuid)
        .await
        .map_err(|e| domain_error_to_problem(e, request_instance))?;
    Ok(Json(to_response(upstream)))
}

pub async fn list_upstreams(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    request_instance: RequestInstance,
    Query(pagination): Query<PaginationQuery>,
) -> Result<impl IntoResponse, Problem> {
    let query = pagination.to_list_query();
    let upstreams = state
        .cp
        .list_upstreams(&ctx, &query)
        .await
        .map_err(|e| domain_error_to_problem(e, request_instance))?;
    let response: Vec<UpstreamResponse> = upstreams.into_iter().map(to_response).collect();
    Ok(Json(response))
}

pub async fn update_upstream(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    request_instance: RequestInstance,
    Path(id): Path<String>,
    Json(req): Json<UpdateUpstreamRequest>,
) -> Result<impl IntoResponse, Problem> {
    let uuid = match parse_gts_id(&id, gts::UPSTREAM_SCHEMA) {
        Ok(uuid) => uuid,
        Err(e) => return Err(domain_error_to_problem(e, request_instance)),
    };
    let upstream = state
        .cp
        .update_upstream(&ctx, uuid, req.into())
        .await
        .map_err(|e| domain_error_to_problem(e, request_instance))?;
    state.backend_selector.invalidate(upstream.id);
    Ok(Json(to_response(upstream)))
}

pub async fn delete_upstream(
    Extension(state): Extension<AppState>,
    Extension(ctx): Extension<SecurityContext>,
    request_instance: RequestInstance,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, Problem> {
    let uuid = match parse_gts_id(&id, gts::UPSTREAM_SCHEMA) {
        Ok(uuid) => uuid,
        Err(e) => return Err(domain_error_to_problem(e, request_instance)),
    };

    state
        .cp
        .delete_upstream(&ctx, uuid)
        .await
        .map_err(|e| domain_error_to_problem(e, request_instance))?;
    state.backend_selector.invalidate(uuid);
    state.dp.remove_rate_limit_key(&format!("upstream:{uuid}"));
    Ok(StatusCode::NO_CONTENT)
}
