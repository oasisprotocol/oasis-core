use std::convert::{Into, TryFrom};
use std::sync::Arc;

use ekiden_common::futures::{future, BoxFuture, Future, Stream};
use ekiden_registry_api as api;
use grpcio::RpcStatusCode::{Internal, InvalidArgument};
use grpcio::{RpcContext, RpcStatus, ServerStreamingSink, UnarySink, WriteFlags};

use super::entity_backend::{EntityRegistryBackend, RegistryEvent};
use ekiden_common::bytes::B256;
use ekiden_common::entity::Entity;
use ekiden_common::error::Error;
use ekiden_common::node::Node;
use ekiden_common::signature::{Signature, Signed};

#[derive(Clone)]
pub struct EntityRegistryService {
    inner: Arc<EntityRegistryBackend>,
}

impl EntityRegistryService {
    pub fn new(backend: Arc<EntityRegistryBackend>) -> Self {
        Self { inner: backend }
    }
}

impl api::EntityRegistry for EntityRegistryService {
    fn register_entity(
        &self,
        ctx: RpcContext,
        req: api::RegisterRequest,
        sink: UnarySink<api::RegisterResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let e = Entity::try_from(req.get_entity().clone())?;
            let s = Signature::try_from(req.get_signature().clone())?;
            Ok(self.inner.register_entity(Signed::from_parts(e, s)))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::RegisterResponse::new()),
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn deregister_entity(
        &self,
        ctx: RpcContext,
        req: api::DeregisterRequest,
        sink: UnarySink<api::DeregisterResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let id = B256::from_slice(req.get_id());
            let s = Signature::try_from(req.get_signature().clone())?;
            Ok(self.inner.deregister_entity(Signed::from_parts(id, s)))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::DeregisterResponse::new()),
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_entity(
        &self,
        ctx: RpcContext,
        req: api::EntityRequest,
        sink: UnarySink<api::EntityResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Entity>, Error> {
            let id = B256::from_slice(req.get_id());
            Ok(self.inner.get_entity(id))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(ent) => {
                    let mut r = api::EntityResponse::new();
                    r.set_entity(ent.into());
                    Ok(r)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_entities(
        &self,
        ctx: RpcContext,
        _req: api::EntitiesRequest,
        sink: UnarySink<api::EntitiesResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Vec<Entity>>, Error> { Ok(self.inner.get_entities()) };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(ent) => {
                    let mut r = api::EntitiesResponse::new();
                    r.set_entity(ent.iter().map(|e| e.to_owned().into()).collect());
                    Ok(r)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn watch_entities(
        &self,
        ctx: RpcContext,
        _req: api::WatchEntityRequest,
        sink: ServerStreamingSink<api::WatchEntityResponse>,
    ) {
        let f = self.inner
            .watch_entities()
            .map(|res| -> (api::WatchEntityResponse, WriteFlags) {
                let mut r = api::WatchEntityResponse::new();
                match res {
                    RegistryEvent::Registered(entity) => {
                        r.set_entity(entity.into());
                        r.set_event_type(api::WatchEntityResponse_ChangeType::REGISTERED);
                    }
                    RegistryEvent::Deregistered(entity) => {
                        r.set_entity(entity.into());
                        r.set_event_type(api::WatchEntityResponse_ChangeType::DEREGISTERED);
                    }
                };
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }

    fn register_node(
        &self,
        ctx: RpcContext,
        req: api::RegisterNodeRequest,
        sink: UnarySink<api::RegisterNodeResponse>,
    ) {
        let f = move || -> Result<BoxFuture<()>, Error> {
            let node = Node::try_from(req.get_node().clone())?;
            let s = Signature::try_from(req.get_signature().clone())?;
            Ok(self.inner.register_node(Signed::from_parts(node, s)))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(()) => Ok(api::RegisterNodeResponse::new()),
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_node(&self, ctx: RpcContext, req: api::NodeRequest, sink: UnarySink<api::NodeResponse>) {
        let f = move || -> Result<BoxFuture<Node>, Error> {
            let id = B256::from_slice(req.get_id());
            Ok(self.inner.get_node(id))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(node) => {
                    let mut r = api::NodeResponse::new();
                    r.set_node(node.into());
                    Ok(r)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_nodes(
        &self,
        ctx: RpcContext,
        req: api::NodesRequest,
        sink: UnarySink<api::NodesResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Vec<Node>>, Error> {
            let epoch = req.get_epoch();
            Ok(self.inner.get_nodes(epoch))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(node) => {
                    let mut r = api::NodesResponse::new();
                    r.set_node(node.iter().map(|n| n.to_owned().into()).collect());
                    Ok(r)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn get_nodes_for_entity(
        &self,
        ctx: RpcContext,
        req: api::EntityNodesRequest,
        sink: UnarySink<api::EntityNodesResponse>,
    ) {
        let f = move || -> Result<BoxFuture<Vec<Node>>, Error> {
            let id = B256::from_slice(req.get_id());
            Ok(self.inner.get_nodes_for_entity(id))
        };
        let f = match f() {
            Ok(f) => f.then(|res| match res {
                Ok(node) => {
                    let mut r = api::EntityNodesResponse::new();
                    r.set_node(node.iter().map(|n| n.to_owned().into()).collect());
                    Ok(r)
                }
                Err(e) => Err(e),
            }),
            Err(e) => {
                ctx.spawn(invalid_rpc!(sink, InvalidArgument, e).map_err(|_e| ()));
                return;
            }
        };
        ctx.spawn(f.then(move |r| match r {
            Ok(ret) => sink.success(ret),
            Err(e) => invalid_rpc!(sink, Internal, e),
        }).map_err(|_e| ()));
    }

    fn watch_nodes(
        &self,
        ctx: RpcContext,
        _req: api::WatchNodeRequest,
        sink: ServerStreamingSink<api::WatchNodeResponse>,
    ) {
        let f = self.inner
            .watch_nodes()
            .map(|res| -> (api::WatchNodeResponse, WriteFlags) {
                let mut r = api::WatchNodeResponse::new();
                match res {
                    RegistryEvent::Registered(node) => {
                        r.set_node(node.into());
                        r.set_event_type(api::WatchNodeResponse_ChangeType::REGISTERED);
                    }
                    RegistryEvent::Deregistered(node) => {
                        r.set_node(node.into());
                        r.set_event_type(api::WatchNodeResponse_ChangeType::DEREGISTERED);
                    }
                };
                (r, WriteFlags::default())
            });
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }

    fn watch_node_list(
        &self,
        ctx: RpcContext,
        _req: api::WatchNodeListRequest,
        sink: ServerStreamingSink<api::WatchNodeListResponse>,
    ) {
        let f = self.inner.watch_node_list().map(
            |(epoch, nodes)| -> (api::WatchNodeListResponse, WriteFlags) {
                let mut r = api::WatchNodeListResponse::new();
                r.set_epoch(epoch);
                r.set_node(nodes.iter().map(|n| n.to_owned().into()).collect());
                (r, WriteFlags::default())
            },
        );
        ctx.spawn(f.forward(sink).then(|_f| future::ok(())));
    }
}
