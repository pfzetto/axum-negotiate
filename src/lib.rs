#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::{borrow::Borrow, ops::Deref};

use async_trait::async_trait;
use libgssapi::{
    context::{SecurityContext, ServerCtx},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_SPNEGO, GSS_NT_KRB5_PRINCIPAL},
};
use log::{debug, error};

use base64::{engine::general_purpose::STANDARD, Engine as _};

use axum_core::{
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use futures_util::future::BoxFuture;
use http::{
    header::{AUTHORIZATION, WWW_AUTHENTICATE},
    request::Parts,
    HeaderValue, Request, StatusCode,
};
use thiserror::Error;
use tower_layer::Layer;
use tower_service::Service;

pub trait NextMiddlewareError: std::error::Error + IntoResponse + Send + Sync {
    fn box_into_response(self: Box<Self>) -> Response;
}
impl<T: std::error::Error + IntoResponse + Send + Sync> NextMiddlewareError for T {
    fn box_into_response(self: Box<Self>) -> Response {
        self.into_response()
    }
}
pub type NextMiddlewareBoxError = Box<dyn NextMiddlewareError>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid characters in spn")]
    InvalidSpn,

    #[error("next middleware: {0}")]
    NextMiddleware(NextMiddlewareBoxError),

    #[error("libgssapi: {0}")]
    GssApi(#[from] libgssapi::error::Error),

    #[error("multistage spnego is requested but currently not supported")]
    MultipassSpnego,

    #[error("invalid authorization header")]
    InvalidAuthorizationHeader,

    #[error("invalid gssapi_data")]
    InvalidGssapiData,

    #[error("UPN extension not found in request")]
    UpnExtensionNotFound,
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Self::InvalidSpn | Self::MultipassSpnego | Self::GssApi(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
            }
            Self::NextMiddleware(error) => error.box_into_response(),
            Self::InvalidGssapiData => (StatusCode::BAD_REQUEST, "bad request").into_response(),
            Self::UpnExtensionNotFound | Self::InvalidAuthorizationHeader => {
                let mut response = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
                response
                    .headers_mut()
                    .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
                response
            }
        }
    }
}

#[derive(Clone)]
pub struct NegotiateAuthLayer {
    spn: String,
}

impl NegotiateAuthLayer {
    pub fn new(spn: String) -> Result<Self, Error> {
        //TODO: check if libgssapi really can't handle utf16 characters. remove the ascii check if
        //it does.
        if spn.is_ascii() {
            Ok(Self { spn })
        } else {
            Err(Error::InvalidSpn)
        }
    }
}

impl<I> Layer<I> for NegotiateAuthLayer {
    type Service = NegotiateAuthLayerMiddleware<I>;

    fn layer(&self, inner: I) -> Self::Service {
        Self::Service {
            inner,
            spn: self.spn.to_owned(),
        }
    }
}

/// The user principal name of the user
#[derive(Clone, Debug)]
pub struct Upn(pub Box<str>);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Upn {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(Error::UpnExtensionNotFound)
    }
}

impl AsRef<str> for Upn {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
impl Borrow<str> for Upn {
    fn borrow(&self) -> &str {
        &self.0
    }
}
impl Deref for Upn {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone)]
pub struct NegotiateAuthLayerMiddleware<I> {
    inner: I,
    spn: String,
}

impl<I, B> Service<Request<B>> for NegotiateAuthLayerMiddleware<I>
where
    I: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    I::Error: NextMiddlewareError,
    I::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = I::Response;

    type Error = Error;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready(cx)
            .map_err(|e| Error::NextMiddleware(Box::new(e)))
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        let spn = self.spn.clone();

        Box::pin(async move {
            let Some(authorization_header) = req
                .headers()
                .get(AUTHORIZATION)
                .and_then(|x| x.to_str().ok())
            else {
                debug!("authorization header not present");
                return Err(Error::InvalidAuthorizationHeader);
            };

            let Some(gssapi_data) = authorization_header.strip_prefix("Negotiate ") else {
                debug!("authorization header has no prefix \"Negotiate\"");
                return Err(Error::InvalidAuthorizationHeader);
            };

            let Ok(gssapi_data) = STANDARD.decode(gssapi_data) else {
                debug!("authorization header gssapi_data contains invalid base64");
                return Err(Error::InvalidGssapiData);
            };

            let mut ctx = new_server_ctx(&spn)?;

            let token = ctx.step(&gssapi_data)?;

            if !ctx.is_complete() {
                error!("currently only 2-pass SPNEGO is supported");
                return Err(Error::MultipassSpnego);
            };

            let upn = ctx.source_name()?.to_string();
            req.extensions_mut().insert(Upn(upn.into()));

            let mut response = inner
                .call(req)
                .await
                .map_err(|x| Error::NextMiddleware(Box::new(x)))?;

            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                format!(
                    "Negotiate {}",
                    token.map(|x| STANDARD.encode(&*x)).unwrap_or_default()
                )
                .parse()
                .expect("base64 to be ascii"),
            );

            Ok(response)
        })
    }
}

fn new_server_ctx(principal: &str) -> Result<ServerCtx, Error> {
    let name = Name::new(principal.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?
        .canonicalize(Some(&GSS_MECH_SPNEGO))?;
    let cred = {
        let mut s = OidSet::new()?;
        s.add(&GSS_MECH_SPNEGO)?;
        Cred::acquire(Some(&name), None, CredUsage::Accept, Some(&s))?
    };
    Ok(ServerCtx::new(cred))
}
