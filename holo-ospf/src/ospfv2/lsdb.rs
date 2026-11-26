//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use holo_utils::ip::{AddressFamily, Ipv4NetworkExt};
use holo_utils::mpls::Label;
use holo_utils::protocol::Protocol;
use holo_utils::sr::{PrefixSidAlgo, Sid, SidLastHopBehavior, SrCfgEvent};
use ipnetwork::{IpNetwork, Ipv4Network};
use itertools::Itertools;

use crate::area::{
    Area, AreaType, AreaVersion, BACKBONE_AREA_ID, OptionsLocation,
};
use crate::collections::{
    AreaIndex, Arena, InterfaceIndex, LsaEntryId, LsdbId, LsdbIndex, lsdb_get,
};
use crate::debug::LsaFlushReason;
use crate::error::Error;
use crate::instance::{InstanceArenas, InstanceUpView};
use crate::interface::{Interface, InterfaceType, ism};
use crate::lsdb::{
    self, LsaEntry, LsaOriginateEvent, LsdbVersion, MAX_LINK_METRIC,
};
use crate::neighbor::nsm;
use crate::northbound::configuration::{ExternalMetricType, RedistributeCfg};
use crate::ospfv2::packet::iana::{
    LsaExtPrefixFlags, LsaOpaqueType, LsaRouterFlags, LsaRouterLinkType,
    LsaTypeCode, Options,
};
use crate::ospfv2::packet::lsa::{
    LsaAsExternal, LsaAsExternalFlags, LsaBody, LsaHdr, LsaNetwork, LsaRouter,
    LsaRouterLink, LsaSummary, LsaType, kind,
};
use crate::ospfv2::packet::lsa_opaque::{
    ExtLinkTlv, ExtPrefixRouteType, ExtPrefixTlv, LsaExtLink, LsaExtPrefix,
    LsaOpaque, LsaRouterInfo, OpaqueLsaId, PrefixSid,
};
use crate::packet::iana::RouterInfoCaps;
use crate::packet::lsa::{
    Lsa, LsaHdrVersion, LsaKey, LsaKind, LsaScope, LsaTypeVersion,
};
use crate::packet::tlv::{
    DynamicHostnameTlv, NodeAdminTagTlv, PrefixSidFlags, RouterInfoCapsTlv,
    SidLabelRangeTlv, SrAlgoTlv, SrLocalBlockTlv,
};
use crate::route::{SummaryNet, SummaryRtr};
use crate::version::Ospfv2;

// ===== impl Ospfv2 =====

// The network address with all host bits set (the broadcast address of
// [net.ip(), net.mask()]).
fn broadcast_addr(net: Ipv4Network) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(net.ip()) | !u32::from(net.mask()))
}

// RFC 2328 Appendix E Link State ID assignment for AS-external LSAs.
// The network number is used whenever it is free; when two prefixes
// share a network number (supernetting / subnet zero), the less
// specific one keeps the network number and the more specific one uses
// the network with all host bits set. Returns the Link State ID for
// `prefix` plus any existing prefixes that must be re-keyed (each as
// (prefix, new LS-ID)), or None when no collision-free assignment
// exists — e.g. a broadcast-form ID already claimed by another prefix,
// or a /32 that cannot move.
fn ext_lsa_id_assignment(
    existing: &BTreeMap<Ipv4Network, (Protocol, Ipv4Addr)>,
    prefix: Ipv4Network,
) -> Option<(Ipv4Addr, Vec<(Ipv4Network, Ipv4Addr)>)> {
    // Reorigination of an already-known prefix keeps its assigned ID.
    if let Some((_, id)) = existing.get(&prefix) {
        return Some((*id, Vec::new()));
    }
    let na = prefix.ip();
    let id_taken_by_other = |id: Ipv4Addr| {
        existing
            .iter()
            .any(|(p, (_, used))| *used == id && *p != prefix)
    };
    let Some(older) = existing
        .iter()
        .find(|(p, (_, id))| *id == na && **p != prefix)
        .map(|(p, _)| *p)
    else {
        return Some((na, Vec::new()));
    };
    if prefix.prefix() > older.prefix() {
        // The new prefix is more specific: it takes the broadcast form
        // of its own network.
        let bcast = broadcast_addr(prefix);
        if id_taken_by_other(bcast) {
            return None;
        }
        Some((bcast, Vec::new()))
    } else {
        // The existing prefix is more specific: it moves to its
        // broadcast form and the new, less specific prefix takes the
        // network number.
        let bcast = broadcast_addr(older);
        if bcast == na || id_taken_by_other(bcast) {
            return None;
        }
        Some((na, vec![(older, bcast)]))
    }
}

// Originates (or reoriginates) one AS-external LSA under a chosen
// Link State ID and records the prefix mapping.
fn orig_external_with_id(
    instance: &mut InstanceUpView<'_, Ospfv2>,
    prefix: Ipv4Network,
    protocol: Protocol,
    cfg: &RedistributeCfg,
    lsa_id: Ipv4Addr,
) {
    let mut flags = LsaAsExternalFlags::empty();
    match cfg.metric_type {
        ExternalMetricType::Type1 => {}
        ExternalMetricType::Type2 => flags |= LsaAsExternalFlags::E,
    }
    let lsa_body = LsaBody::AsExternal(LsaAsExternal {
        mask: prefix.mask(),
        flags,
        metric: cfg.metric,
        fwd_addr: None,
        tag: 0,
    });
    instance.tx.protocol_input.lsa_orig_check(
        LsdbId::As,
        None,
        lsa_id,
        lsa_body,
    );
    instance
        .state
        .external_lsas
        .insert(prefix, (protocol, lsa_id));
}

impl LsdbVersion<Self> for Ospfv2 {
    fn lsa_orig_external(
        instance: &mut InstanceUpView<'_, Self>,
        arenas: &InstanceArenas<Self>,
        prefix: Ipv4Network,
        protocol: Protocol,
        cfg: &RedistributeCfg,
    ) {
        // RFC 2328: an ASBR attached only to stub/NSSA areas must not
        // originate AS-external (Type-5) LSAs.
        if !arenas
            .areas
            .iter()
            .any(|area| area.config.area_type == AreaType::Normal)
        {
            return;
        }

        // RFC 2328 Appendix E: the Link State ID is the network number
        // whenever free; prefixes sharing a network number are spread
        // across the network-number / broadcast-form slots.
        let (lsa_id, rekeys) = match ext_lsa_id_assignment(
            &instance.state.external_lsas,
            prefix,
        ) {
            Some(assignment) => assignment,
            None => {
                tracing::warn!(
                    %prefix,
                    "no collision-free Type-5 Link State ID (RFC 2328 Appendix E); skipping origination"
                );
                return;
            }
        };
        for (older, new_id) in rekeys {
            let Some((older_proto, _)) =
                instance.state.external_lsas.get(&older).cloned()
            else {
                continue;
            };
            let Some(older_cfg) =
                instance.config.redistribution.get(&older_proto)
            else {
                // Without the redistribution entry we cannot re-originate
                // the displaced prefix; originating the new one would
                // silently overwrite it. Bail out conservatively.
                tracing::warn!(
                    %older,
                    "redistribution config missing during Link State ID re-key; skipping"
                );
                return;
            };
            orig_external_with_id(
                instance,
                older,
                older_proto,
                older_cfg,
                new_id,
            );
        }
        orig_external_with_id(instance, prefix, protocol, cfg, lsa_id);
    }

    fn lsa_flush_external(
        instance: &mut InstanceUpView<'_, Self>,
        arenas: &InstanceArenas<Self>,
        prefix: Ipv4Network,
    ) {
        let Some((_, lsa_id)) = instance.state.external_lsas.remove(&prefix)
        else {
            return;
        };
        let adv_rtr = instance.state.router_id;
        if let Some((_, lse)) = instance
            .state
            .lsdb
            .iter_by_type_advrtr(
                &arenas.lsa_entries,
                kind::AsExternal.lsa_type(),
                adv_rtr,
            )
            .find(|(_, lse)| lse.data.hdr.lsa_id() == lsa_id)
        {
            let lse_id = lse.id;
            instance.tx.protocol_input.lsa_flush(
                LsdbId::As,
                lse_id,
                LsaFlushReason::RedistributionRemoved,
            );
        }
    }

    fn lsa_type_is_valid(
        area_type: Option<AreaType>,
        if_type: Option<InterfaceType>,
        nbr_options: Option<Options>,
        lsa_type: LsaType,
    ) -> bool {
        // Reject LSAs of unknown type.
        if lsa_type.type_code().is_none() {
            return false;
        }

        // Opaque LSAs are only flooded to opaque-capable neighbors.
        if let Some(nbr_options) = nbr_options
            && lsa_type.is_opaque()
            && !nbr_options.contains(Options::O)
        {
            return false;
        }

        // Reject AS-external LSAs over virtual links.
        if let Some(if_type) = if_type
            && if_type == InterfaceType::VirtualLink
            && matches!(
                lsa_type.type_code(),
                Some(LsaTypeCode::AsExternal | LsaTypeCode::OpaqueAs)
            )
        {
            return false;
        }

        // Reject AS-external and type-4 summary LSAs (as per errata 3746 of RFC
        // 2328) on stub/NSSA areas.
        if let Some(area_type) = area_type
            && area_type != AreaType::Normal
            && matches!(
                lsa_type.type_code(),
                Some(
                    LsaTypeCode::SummaryRouter
                        | LsaTypeCode::AsExternal
                        | LsaTypeCode::OpaqueAs
                )
            )
        {
            return false;
        }

        true
    }

    fn lsa_is_self_originated(
        lsa: &Lsa<Self>,
        router_id: Ipv4Addr,
        interfaces: &Arena<Interface<Self>>,
    ) -> bool {
        // 1) The LSA's Advertising Router is equal to the router's own Router
        // ID.
        if lsa.hdr.adv_rtr == router_id {
            return true;
        }

        // 2) The LSA is a network-LSA and its Link State ID is equal to one of
        // the router's own IP interface addresses.
        if lsa.hdr.lsa_type.type_code() == Some(LsaTypeCode::Network)
            && interfaces
                .iter()
                .filter_map(|(_, iface)| iface.system.primary_addr)
                .any(|iface_primary_addr| {
                    lsa.hdr.lsa_id == iface_primary_addr.ip()
                })
        {
            return true;
        }

        false
    }

    fn lsa_orig_event(
        instance: &InstanceUpView<'_, Self>,
        arenas: &InstanceArenas<Self>,
        event: LsaOriginateEvent,
    ) -> Result<(), Error<Self>> {
        match event {
            LsaOriginateEvent::AreaStart { area_id } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // Originate Router Information LSA(s).
                lsa_orig_router_info(area, instance);
            }
            LsaOriginateEvent::InterfaceStateChange { area_id, .. } => {
                // (Re)originate Router-LSA in all areas since the ABR status
                // might have changed.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }

                // (Re)originate Extended Prefix Opaque LSA(s) since the set of
                // loopback interfaces with the node flag might have changed.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_ext_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceDrChange { area_id, iface_id }
            | LsaOriginateEvent::GrHelperExit { area_id, iface_id } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate or flush Network-LSA.
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if iface.state.ism_state == ism::State::Dr
                    && iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full)
                {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }
            }
            LsaOriginateEvent::InterfaceAddrAddDel { area_id, .. } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Extended Prefix Opaque LSA(s) since the set of
                // loopback host prefixes might have changed.
                lsa_orig_ext_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceCostChange { area_id } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);
            }
            LsaOriginateEvent::InterfaceFlagChange { area_id } => {
                // (Re)originate Extended Prefix Opaque LSA(s).
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_ext_prefix(area, instance, arenas);
            }
            LsaOriginateEvent::NeighborToFromFull { area_id, iface_id } => {
                // (Re)originate Router-LSA.
                let (_, area) = arenas.areas.get_by_id(area_id)?;
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Extended Link Opaque LSA(s).
                lsa_orig_ext_link(area, instance, arenas);

                // (Re)originate Network-LSA.
                let (_, iface) =
                    area.interfaces.get_by_id(&arenas.interfaces, iface_id)?;
                if iface.state.ism_state == ism::State::Dr
                    && iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full)
                {
                    lsa_orig_network(iface, area, instance, arenas);
                } else {
                    lsa_flush_network(iface, area, instance, arenas);
                }

                // For virtual links, reoriginate the Router-LSA in the
                // associated transit area.
                if let Some(vlink_key) = &iface.vlink_key
                    && let Some((_, transit_area)) =
                        arenas.areas.get_by_area_id(vlink_key.transit_area_id)
                {
                    lsa_orig_router(transit_area, instance, arenas);
                }
            }
            LsaOriginateEvent::NeighborTwoWayOrHigherChange {
                area_id, ..
            } => {
                let (_, area) = arenas.areas.get_by_id(area_id)?;

                // (Re)originate Router-LSA.
                lsa_orig_router(area, instance, arenas);

                // (Re)originate Extended Link Opaque LSA(s).
                lsa_orig_ext_link(area, instance, arenas);
            }
            LsaOriginateEvent::VirtualLinkChange => {
                // (Re)originate Router-LSA in the backbone area.
                if let Some((_, backbone)) =
                    arenas.areas.get_by_area_id(BACKBONE_AREA_ID)
                {
                    lsa_orig_router(backbone, instance, arenas);
                }
            }
            LsaOriginateEvent::SelfOriginatedLsaRcvd { lsdb_id, lse_id } => {
                // Check if the received self-originated LSA needs to be
                // reoriginated or flushed.
                process_self_originated_lsa(instance, arenas, lsdb_id, lse_id)?;
            }
            LsaOriginateEvent::StubRouterChange => {
                // (Re)originate Router-LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }
            }
            LsaOriginateEvent::RedistributionChange => {
                // (Re)originate Router-LSA(s) in all areas: the E
                // (ASBR) bit depends on the redistribution config.
                for area in arenas.areas.iter() {
                    lsa_orig_router(area, instance, arenas);
                }
            }
            LsaOriginateEvent::GrHelperChange => {
                // (Re)originate Router Information LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                }
            }
            LsaOriginateEvent::SrEnableChange => {
                // (Re)originate Router Information LSA(s), Extended Prefix
                // Opaque LSA(s) and Extended Link Opaque LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                    lsa_orig_ext_prefix(area, instance, arenas);
                    lsa_orig_ext_link(area, instance, arenas);
                }
            }
            LsaOriginateEvent::SrCfgChange { change } => {
                match change {
                    SrCfgEvent::LabelRangeUpdate => {
                        // Reoriginate Router Information LSA(s) in all areas.
                        for area in arenas.areas.iter() {
                            lsa_orig_router_info(area, instance);
                        }
                    }
                    SrCfgEvent::PrefixSidUpdate(af) => {
                        if af == AddressFamily::Ipv4 {
                            // (Re)originate Extended Prefix Opaque LSA(s) in
                            // all areas.
                            for area in arenas.areas.iter() {
                                lsa_orig_ext_prefix(area, instance, arenas);
                            }
                        }
                    }
                }
            }
            LsaOriginateEvent::HostnameChange
            | LsaOriginateEvent::NodeTagsChange => {
                // (Re)originate Router Information LSA(s) in all areas.
                for area in arenas.areas.iter() {
                    lsa_orig_router_info(area, instance);
                }
            }
            _ => (),
        };

        Ok(())
    }

    fn lsa_orig_inter_area_network(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        prefix: Ipv4Network,
        _lsa_id: Option<u32>,
        summary: &SummaryNet<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);

        // LSA's header options.
        let options = Self::area_options(area, OptionsLocation::Lsa);

        // TODO: implement Appendix's E algorithm for assigning Link State IDs.
        let lsa_id = prefix.ip();

        // (Re)originate Type-3 Summary-LSA.
        let lsa_body = LsaBody::SummaryNetwork(LsaSummary {
            mask: prefix.mask(),
            metric: summary.metric,
        });
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(options),
            lsa_id,
            lsa_body,
        );

        lsa_id.into()

        // TODO: propagate SR Prefix-SIDs separately.
    }

    fn lsa_orig_inter_area_router(
        area: &mut Area<Self>,
        instance: &InstanceUpView<'_, Self>,
        router_id: Ipv4Addr,
        _lsa_id: Option<u32>,
        summary: &SummaryRtr<Self>,
    ) -> u32 {
        let lsdb_id = LsdbId::Area(area.id);

        // LSA ID.
        let lsa_id = router_id;

        // (Re)originate Type-4 Summary-LSA.
        let lsa_body = LsaBody::SummaryRouter(LsaSummary {
            mask: Ipv4Addr::BROADCAST,
            metric: summary.metric,
        });
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(summary.options),
            lsa_id,
            lsa_body,
        );

        lsa_id.into()
    }

    fn lsdb_get_by_lsa_type(
        iface_idx: InterfaceIndex,
        area_idx: AreaIndex,
        lsa_type: LsaType,
    ) -> LsdbIndex {
        match lsa_type.scope() {
            LsaScope::Link => LsdbIndex::Link(area_idx, iface_idx),
            LsaScope::Area => LsdbIndex::Area(area_idx),
            LsaScope::As => LsdbIndex::As,
            LsaScope::Unknown => {
                unreachable!();
            }
        }
    }

    fn lsdb_install(
        instance: &mut InstanceUpView<'_, Self>,
        arenas: &mut InstanceArenas<Self>,
        lsdb_idx: LsdbIndex,
        _lsdb_id: LsdbId,
        lsa: &Lsa<Self>,
    ) {
        // Keep track of self-originated Network-LSAs in the corresponding
        // interface structures. This is necessary to allow flushing those LSAs
        // later, since the interface address might change.
        if lsa.hdr.lsa_type.type_code() == Some(LsaTypeCode::Network)
            && lsa.hdr.adv_rtr == instance.state.router_id
        {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &mut arenas.areas[area_idx];
            if let Some((_, iface)) = area
                .interfaces
                .get_mut_by_addr(&mut arenas.interfaces, lsa.hdr.lsa_id)
            {
                if lsa.hdr.is_maxage() {
                    iface.state.network_lsa_self = None;
                } else {
                    iface.state.network_lsa_self = Some(lsa.hdr.key());
                }
            }
        }

        // Update hostname database.
        if let LsaBody::OpaqueArea(LsaOpaque::RouterInfo(router_info))
        | LsaBody::OpaqueAs(LsaOpaque::RouterInfo(router_info)) = &lsa.body
        {
            if let Some(hostname_tlv) = router_info.info_hostname.as_ref() {
                // Install or update hostname.
                instance
                    .state
                    .hostnames
                    .insert(lsa.hdr.adv_rtr, hostname_tlv.hostname.clone());
            } else {
                // Remove hostname if it exists.
                instance.state.hostnames.remove(&lsa.hdr.adv_rtr);
            }
        }
    }
}

// ===== helper functions =====

fn lsa_orig_router(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Router-LSA's flags.
    let mut flags = LsaRouterFlags::empty();
    if !instance.config.redistribution.is_empty()
        && area.config.area_type == AreaType::Normal
    {
        // This router originates AS-external LSAs: advertise the E
        // (ASBR) bit so that peers install the external routes. The
        // E-bit is forbidden in Router-LSAs flooded into stub areas.
        flags.insert(LsaRouterFlags::E);
    }
    if arenas.areas.is_abr(&arenas.interfaces) {
        flags.insert(LsaRouterFlags::B);
    }
    if lsdb::router_lsa_v_bit(area, arenas) {
        flags.insert(LsaRouterFlags::V);
    }

    // Router-LSA's links.
    let mut links = vec![];
    for iface in area
        .interfaces
        .iter(&arenas.interfaces)
        // Skip interfaces in the "Down" state.
        .filter(|iface| !iface.is_down())
    {
        // Add Type-3 (stub) links to interfaces in Loopback state.
        if iface.state.ism_state == ism::State::Loopback {
            links.extend(iface.system.addr_list.keys().map(|addr| {
                LsaRouterLink::new(
                    LsaRouterLinkType::StubNetwork,
                    addr.ip(),
                    Ipv4Addr::BROADCAST,
                    0,
                )
            }));
            continue;
        }

        // When stub-router is configured (RFC 6987), set the cost of all
        // non-stub links to MaxLinkMetric.
        let non_stub_cost = if instance.config.stub_router {
            MAX_LINK_METRIC
        } else if let Some(vlink_state) = &iface.state.vlink {
            vlink_state.cost
        } else {
            iface.config.cost
        };

        let mut add_stub_links = false;
        match iface.config.if_type {
            InterfaceType::PointToPoint | InterfaceType::PointToMultipoint => {
                // Add a Type-1 link (p2p) for each fully adjacent neighbor.
                let primary_addr = iface.system.primary_addr.unwrap();
                for nbr in iface
                    .state
                    .neighbors
                    .iter(&arenas.neighbors)
                    .filter(|nbr| nbr.state == nsm::State::Full)
                {
                    let link_data = if iface.system.is_unnumbered() {
                        Ipv4Addr::from(iface.system.ifindex.unwrap())
                    } else {
                        primary_addr.ip()
                    };
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::PointToPoint,
                        nbr.router_id,
                        link_data,
                        non_stub_cost,
                    );
                    links.push(link);
                }

                // Add Type-3 (stub) links, unless the interface is unnumbered.
                if !iface.system.is_unnumbered() {
                    if iface.config.if_type == InterfaceType::PointToMultipoint
                    {
                        // Point-to-multipoint interfaces advertise host
                        // routes to the interface addresses instead (RFC
                        // 2328, section 12.4.1.4).
                        links.extend(iface.system.addr_list.keys().map(
                            |addr| {
                                LsaRouterLink::new(
                                    LsaRouterLinkType::StubNetwork,
                                    addr.ip(),
                                    Ipv4Addr::BROADCAST,
                                    0,
                                )
                            },
                        ));
                    } else {
                        add_stub_links = true;
                    }
                }
            }
            InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                let primary_addr = iface.system.primary_addr.unwrap();
                if iface.state.ism_state == ism::State::Waiting {
                    // Add Type-3 (stub) links.
                    add_stub_links = true;
                } else if (iface.state.ism_state == ism::State::Dr
                    && iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .any(|nbr| nbr.state == nsm::State::Full))
                    || iface
                        .state
                        .dr
                        .and_then(|net_id| {
                            iface
                                .state
                                .neighbors
                                .get_by_net_id(&arenas.neighbors, net_id)
                                .filter(|(_, nbr)| {
                                    nbr.state == nsm::State::Full
                                })
                        })
                        .is_some()
                {
                    // Add a Type-2 (transit) link.
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::TransitNetwork,
                        iface.state.dr.unwrap().get(),
                        primary_addr.ip(),
                        non_stub_cost,
                    );
                    links.push(link);
                } else {
                    // Add Type-3 (stub) links.
                    add_stub_links = true;
                }
            }
            InterfaceType::VirtualLink => {
                if let Some(nbr) =
                    iface.state.neighbors.iter(&arenas.neighbors).next()
                    && nbr.state == nsm::State::Full
                {
                    let link = LsaRouterLink::new(
                        LsaRouterLinkType::VirtualLink,
                        nbr.router_id,
                        iface.state.src_addr.unwrap(),
                        non_stub_cost,
                    );
                    links.push(link);
                }
            }
        }

        if add_stub_links {
            links.extend(
                iface
                    .system
                    .addr_list
                    .keys()
                    .map(|addr| addr.apply_mask())
                    .map(|addr| {
                        LsaRouterLink::new(
                            LsaRouterLinkType::StubNetwork,
                            addr.ip(),
                            addr.mask(),
                            iface.config.cost,
                        )
                    }),
            );
        }
    }

    // (Re)originate Router-LSA.
    let lsa_body = LsaBody::Router(LsaRouter { flags, links });
    instance.tx.protocol_input.lsa_orig_check(
        lsdb_id,
        Some(options),
        instance.state.router_id,
        lsa_body,
    );
}

fn lsa_orig_network(
    iface: &Interface<Ospfv2>,
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // The Link State ID for a network-LSA is the IP interface address of the
    // Designated Router.
    let lsa_id = iface.system.primary_addr.unwrap().ip();

    // Network-LSA's mask.
    let mask = iface.system.primary_addr.unwrap().mask();

    // Network-LSA's attached routers.
    let myself = instance.state.router_id;
    let nbrs = iface
        .state
        .neighbors
        .iter(&arenas.neighbors)
        .filter(|nbr| nbr.state == nsm::State::Full)
        .map(|nbr| nbr.router_id);
    let attached_rtrs = std::iter::once(myself).chain(nbrs).collect();

    // (Re)originate Network-LSA.
    let lsa_body = LsaBody::Network(LsaNetwork {
        mask,
        attached_rtrs,
    });
    instance.tx.protocol_input.lsa_orig_check(
        lsdb_id,
        Some(options),
        lsa_id,
        lsa_body,
    );
}

fn lsa_flush_network(
    iface: &Interface<Ospfv2>,
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    if let Some(lsa_key) = &iface.state.network_lsa_self {
        lsa_flush_area(area, instance, &arenas.lsa_entries, lsa_key);
    }
}

fn lsa_orig_router_info(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
) {
    let sr_config = &instance.shared.sr_config;
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Initialize Opaque LSA ID.
    let lsa_id = OpaqueLsaId::new(LsaOpaqueType::RouterInfo as u8, 0).into();

    let mut sr_algo = None;
    let mut srgb = vec![];
    let mut srlb = vec![];
    if instance.config.sr_enabled {
        // Fill in supported SR algorithms.
        sr_algo = Some(SrAlgoTlv::new([PrefixSidAlgo::Spf as u8].into()));

        // Fill in local SRGB.
        for range in &sr_config.srgb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srgb.push(SidLabelRangeTlv::new(first, range));
        }

        // Fill in local SRLB.
        for range in &sr_config.srlb {
            let first = Sid::Label(Label::new(range.lower_bound));
            let range = range.upper_bound - range.lower_bound + 1;
            srlb.push(SrLocalBlockTlv::new(first, range));
        }
    }

    // Fill in node tags.
    let mut node_tags = vec![];
    if !instance.config.node_tags.is_empty() {
        node_tags.push(NodeAdminTagTlv::new(instance.config.node_tags.clone()));
    }

    // (Re)originate Router Information LSA.
    let mut info_caps = RouterInfoCaps::STUB_ROUTER;
    if instance.config.gr.helper_enabled {
        info_caps.insert(RouterInfoCaps::GR_HELPER);
    }
    let lsa_body = LsaBody::OpaqueArea(LsaOpaque::RouterInfo(LsaRouterInfo {
        info_caps: Some(RouterInfoCapsTlv::new(info_caps)),
        func_caps: None,
        sr_algo,
        srgb,
        srlb,
        msds: None,
        srms_pref: None,
        info_hostname: instance
            .shared
            .hostname
            .as_ref()
            .map(|hostname| DynamicHostnameTlv::new(hostname.to_string())),
        node_tags,
        unknown_tlvs: vec![],
    }));
    instance.tx.protocol_input.lsa_orig_check(
        lsdb_id,
        Some(options),
        lsa_id,
        lsa_body,
    );
}

fn lsa_orig_ext_prefix(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let sr_config = &instance.shared.sr_config;
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Initialize prefixes.
    let mut prefixes = BTreeMap::new();

    // Add Prefix-SIDs.
    if instance.config.sr_enabled {
        for ((prefix, algo), prefix_sid) in sr_config.prefix_sids.iter() {
            if let IpNetwork::V4(prefix) = prefix {
                // Add Prefix-SID Sub-TLV.
                let mut psid_flags = PrefixSidFlags::empty();
                match prefix_sid.last_hop {
                    SidLastHopBehavior::ExpNull => {
                        psid_flags.insert(PrefixSidFlags::NP);
                        psid_flags.insert(PrefixSidFlags::E);
                    }
                    SidLastHopBehavior::NoPhp => {
                        psid_flags.insert(PrefixSidFlags::NP);
                    }
                    SidLastHopBehavior::Php => (),
                }
                let sid = Sid::Index(prefix_sid.index);
                let algo = *algo as u8;
                prefixes
                    .entry(*prefix)
                    .or_insert_with(|| {
                        ExtPrefixTlv::new(
                            ExtPrefixRouteType::IntraArea,
                            0,
                            LsaExtPrefixFlags::empty(),
                            *prefix,
                        )
                    })
                    .prefix_sids
                    .insert(algo, PrefixSid::new(psid_flags, algo, sid));
            }
        }
    }

    // Set the N-flag (RFC 7684) and AC-flag (RFC 9983) on interface
    // prefixes that have the corresponding flag configured.
    for (prefix, flags) in area
        .interfaces
        .iter(&arenas.interfaces)
        .filter(|iface| !iface.is_down())
        .flat_map(|iface| {
            iface.system.addr_list.keys().filter_map(move |addr| {
                let mut flags = LsaExtPrefixFlags::empty();
                if iface.config.node_flag
                    && iface.state.ism_state == ism::State::Loopback
                    && addr.is_host_prefix()
                {
                    flags.insert(LsaExtPrefixFlags::N);
                } else if iface.config.anycast_flag {
                    flags.insert(LsaExtPrefixFlags::AC);
                }
                if flags.is_empty() {
                    return None;
                }
                Some((addr.apply_mask(), flags))
            })
        })
    {
        prefixes
            .entry(prefix)
            .and_modify(|tlv| tlv.flags.insert(flags))
            .or_insert_with(|| {
                ExtPrefixTlv::new(
                    ExtPrefixRouteType::IntraArea,
                    0,
                    flags,
                    prefix,
                )
            });
    }

    // (Re)originate as many Extended Prefix Opaque LSAs as necessary.
    let mut opaque_id: u32 = 0;
    let mut originate_fn = |prefixes| {
        // Initialize Opaque LSA ID.
        let lsa_id =
            OpaqueLsaId::new(LsaOpaqueType::ExtPrefix as u8, opaque_id).into();

        // (Re)originate Extended Prefix Opaque LSA.
        let lsa_body =
            LsaBody::OpaqueArea(LsaOpaque::ExtPrefix(LsaExtPrefix {
                prefixes,
            }));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(options),
            lsa_id,
            lsa_body,
        );

        // Increment the Opaque ID.
        opaque_id += 1;
    };
    for prefixes in prefixes
        .into_iter()
        .chunks(
            (Lsa::<Ospfv2>::MAX_LENGTH - LsaHdr::LENGTH as usize)
                / ExtPrefixTlv::BASE_LENGTH as usize,
        )
        .into_iter()
    {
        originate_fn(prefixes.collect());
    }

    // Flush self-originated Extended Prefix Opaque LSAs that are no longer
    // needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaTypeCode::OpaqueArea.into(),
            instance.state.router_id,
        )
        .filter(|(_, lse)| {
            let opaque_lsa_id = OpaqueLsaId::from(lse.data.hdr.lsa_id);
            opaque_lsa_id.opaque_type == LsaOpaqueType::ExtPrefix as u8
                && opaque_lsa_id.opaque_id >= opaque_id
        })
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_orig_ext_link(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
) {
    let lsdb_id = LsdbId::Area(area.id);

    // LSA's header options.
    let options = Ospfv2::area_options(area, OptionsLocation::Lsa);

    // Originate as many Extended Link Opaque LSAs as necessary.
    let mut opaque_id: u32 = 0;
    let mut originate_fn = |link_tlv| {
        // Initialize Opaque LSA ID.
        let lsa_id =
            OpaqueLsaId::new(LsaOpaqueType::ExtLink as u8, opaque_id).into();

        // (Re)originate Extended Link Opaque LSA.
        let lsa_body = LsaBody::OpaqueArea(LsaOpaque::ExtLink(LsaExtLink {
            link: Some(link_tlv),
        }));
        instance.tx.protocol_input.lsa_orig_check(
            lsdb_id,
            Some(options),
            lsa_id,
            lsa_body,
        );

        // Increment the Opaque ID.
        opaque_id += 1;
    };

    if instance.config.sr_enabled {
        for iface in area
            .interfaces
            .iter(&arenas.interfaces)
            // Skip interfaces in the "Down" state.
            .filter(|iface| !iface.is_down())
            // Skip loopback interfaces.
            .filter(|iface| iface.state.ism_state != ism::State::Loopback)
        {
            let primary_addr = iface.system.primary_addr.unwrap();
            match iface.config.if_type {
                InterfaceType::PointToPoint
                | InterfaceType::PointToMultipoint => {
                    for nbr in iface
                        .state
                        .neighbors
                        .iter(&arenas.neighbors)
                        .filter(|nbr| nbr.state == nsm::State::Full)
                    {
                        let link_data = if iface.system.is_unnumbered() {
                            Ipv4Addr::from(iface.system.ifindex.unwrap())
                        } else {
                            primary_addr.ip()
                        };
                        let link_tlv = ExtLinkTlv::new(
                            LsaRouterLinkType::PointToPoint,
                            nbr.router_id,
                            link_data,
                            nbr.adj_sids.clone(),
                            None,
                        );
                        originate_fn(link_tlv);
                    }
                }
                InterfaceType::Broadcast | InterfaceType::NonBroadcast => {
                    if (iface.state.ism_state == ism::State::Dr
                        && iface
                            .state
                            .neighbors
                            .iter(&arenas.neighbors)
                            .any(|nbr| nbr.state == nsm::State::Full))
                        || iface
                            .state
                            .dr
                            .and_then(|net_id| {
                                iface
                                    .state
                                    .neighbors
                                    .get_by_net_id(&arenas.neighbors, net_id)
                                    .filter(|(_, nbr)| {
                                        nbr.state == nsm::State::Full
                                    })
                            })
                            .is_some()
                    {
                        let adj_sids = iface
                            .state
                            .neighbors
                            .iter(&arenas.neighbors)
                            .flat_map(|nbr| nbr.adj_sids.iter())
                            .copied()
                            .collect();
                        let link_tlv = ExtLinkTlv::new(
                            LsaRouterLinkType::TransitNetwork,
                            iface.state.dr.unwrap().get(),
                            primary_addr.ip(),
                            adj_sids,
                            None,
                        );
                        originate_fn(link_tlv);
                    };
                }
                InterfaceType::VirtualLink => {
                    // Ignore virtual links.
                }
            }
        }
    }

    // Flush self-originated Extended Link Opaque LSAs that are no longer
    // needed.
    for (_, lse) in area
        .state
        .lsdb
        .iter_by_type_advrtr(
            &arenas.lsa_entries,
            LsaTypeCode::OpaqueArea.into(),
            instance.state.router_id,
        )
        .filter(|(_, lse)| {
            let opaque_lsa_id = OpaqueLsaId::from(lse.data.hdr.lsa_id);
            opaque_lsa_id.opaque_type == LsaOpaqueType::ExtLink as u8
                && opaque_lsa_id.opaque_id >= opaque_id
        })
    {
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn process_self_originated_lsa(
    instance: &InstanceUpView<'_, Ospfv2>,
    arenas: &InstanceArenas<Ospfv2>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) -> Result<(), Error<Ospfv2>> {
    let mut flush = false;

    // Lookup LSDB and LSA entry.
    let (lsdb_idx, lsdb) = lsdb_get(
        &instance.state.lsdb,
        &arenas.areas,
        &arenas.interfaces,
        &lsdb_id.into(),
    )?;
    let (_, lse) = lsdb.get_by_id(&arenas.lsa_entries, lse_id)?;
    let lsa = &lse.data;

    // Check LSA type.
    match lsa.hdr.lsa_type.type_code() {
        Some(LsaTypeCode::Router) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Reoriginate Router-LSA.
            lsa_orig_router(area, instance, arenas);
        }
        Some(LsaTypeCode::Network) => {
            let area_idx = lsdb_idx.into_area().unwrap();
            let area = &arenas.areas[area_idx];

            // Check if the router is still the DR for the network.
            if let Some(iface) = area
                .interfaces
                .iter(&arenas.interfaces)
                .find(|iface| {
                    iface.system.primary_addr.unwrap().ip() == lsa.hdr.lsa_id
                })
                .filter(|iface| iface.state.ism_state == ism::State::Dr)
                .filter(|_| {
                    // Ensure the Router-ID hasn't changed.
                    lsa.hdr.adv_rtr == instance.state.router_id
                })
            {
                // Reoriginate Network-LSA.
                lsa_orig_network(iface, area, instance, arenas);
            } else {
                // Flush Network-LSA.
                flush = true;
            }
        }
        Some(LsaTypeCode::SummaryNetwork | LsaTypeCode::SummaryRouter) => {
            // Do nothing. These LSAs will be either reoriginated or flushed
            // once SPF runs and the routing table is computed.
        }
        Some(LsaTypeCode::AsExternal) => {
            // Flush AS-External-LSA (redistribution of local routes isn't
            // supported at the moment).
            flush = true;
        }
        Some(
            LsaTypeCode::OpaqueLink
            | LsaTypeCode::OpaqueArea
            | LsaTypeCode::OpaqueAs,
        ) => {
            // Flush Opaque-LSA.
            flush = true;
        }
        None => {
            // Receiving self-originated LSAs of unknown type shouldn't happen
            // in practice. If it does, the LSA will be rejected early on before
            // it reaches this point.
            flush = true;
        }
    }

    if flush {
        // Effetively flush the received self-originated LSA.
        lsa_flush(instance, lsdb_id, lse_id);
    }

    Ok(())
}

fn lsa_flush_area(
    area: &Area<Ospfv2>,
    instance: &InstanceUpView<'_, Ospfv2>,
    lsa_entries: &Arena<LsaEntry<Ospfv2>>,
    lsa_key: &LsaKey<LsaType>,
) {
    if let Some((_, lse)) = area.state.lsdb.get(lsa_entries, lsa_key) {
        let lsdb_id = LsdbId::Area(area.id);
        lsa_flush(instance, lsdb_id, lse.id);
    }
}

fn lsa_flush(
    instance: &InstanceUpView<'_, Ospfv2>,
    lsdb_id: LsdbId,
    lse_id: LsaEntryId,
) {
    instance.tx.protocol_input.lsa_flush(
        lsdb_id,
        lse_id,
        LsaFlushReason::PrematureAging,
    );
}

// ===== tests =====

#[cfg(test)]
mod tests {
    use super::*;

    fn net(prefix: &str) -> Ipv4Network {
        prefix.parse().unwrap()
    }

    fn addr(ip: &str) -> Ipv4Addr {
        ip.parse().unwrap()
    }

    fn mapping(
        entries: &[(&str, &str)],
    ) -> BTreeMap<Ipv4Network, (Protocol, Ipv4Addr)> {
        entries
            .iter()
            .map(|(p, id)| (net(p), (Protocol::KERNEL, addr(id))))
            .collect()
    }

    #[test]
    fn network_number_used_when_free() {
        let e = mapping(&[]);
        assert_eq!(
            ext_lsa_id_assignment(&e, net("10.0.0.0/24")).unwrap().0,
            addr("10.0.0.0")
        );
    }

    #[test]
    fn reorigination_keeps_assigned_id() {
        let e = mapping(&[("10.0.0.0/24", "10.0.0.255")]);
        assert_eq!(
            ext_lsa_id_assignment(&e, net("10.0.0.0/24")).unwrap().0,
            addr("10.0.0.255")
        );
    }

    #[test]
    fn more_specific_arriving_second_uses_broadcast_form() {
        // /8 holds 10.0.0.0; the new /24 takes its broadcast form.
        let e = mapping(&[("10.0.0.0/8", "10.0.0.0")]);
        let (id, rekeys) =
            ext_lsa_id_assignment(&e, net("10.0.0.0/24")).unwrap();
        assert_eq!(id, addr("10.0.0.255"));
        assert!(rekeys.is_empty());
    }

    #[test]
    fn less_specific_arriving_second_rekeys_existing() {
        // RFC 2328 Appendix E example steps (1)-(2): /24 holds
        // 10.0.0.0; /16 arrives, takes 10.0.0.0, /24 moves to
        // 10.0.0.255.
        let e = mapping(&[("10.0.0.0/24", "10.0.0.0")]);
        let (id, rekeys) =
            ext_lsa_id_assignment(&e, net("10.0.0.0/16")).unwrap();
        assert_eq!(id, addr("10.0.0.0"));
        assert_eq!(rekeys, vec![(net("10.0.0.0/24"), addr("10.0.0.255"))]);
    }

    #[test]
    fn three_way_rfc_example() {
        // After steps (1)-(2) of the RFC example, /8 arrives: it takes
        // 10.0.0.0 and the /16 moves to 10.0.255.255; the /24 keeps
        // 10.0.0.255.
        let e = mapping(&[
            ("10.0.0.0/24", "10.0.0.255"),
            ("10.0.0.0/16", "10.0.0.0"),
        ]);
        let (id, rekeys) =
            ext_lsa_id_assignment(&e, net("10.0.0.0/8")).unwrap();
        assert_eq!(id, addr("10.0.0.0"));
        assert_eq!(rekeys, vec![(net("10.0.0.0/16"), addr("10.0.255.255"))]);
    }

    #[test]
    fn broadcast_form_collision_is_unrepresentable() {
        // The /24's broadcast form 10.0.0.255 is already claimed by a
        // host route: no collision-free ID exists.
        let e = mapping(&[
            ("10.0.0.0/8", "10.0.0.0"),
            ("10.0.0.255/32", "10.0.0.255"),
        ]);
        assert!(ext_lsa_id_assignment(&e, net("10.0.0.0/24")).is_none());
    }

    #[test]
    fn independent_withdrawal_of_colliding_prefix() {
        // /8 and /24 coexist per Appendix E: /8 holds 10.0.0.0, the
        // /24 holds its broadcast form 10.0.0.255. Withdrawing the /8
        // (lsa_flush_external removes exactly the prefix's mapping)
        // must leave the /24 untouched, and the freed network number
        // must be reusable without re-keying the survivor.
        let mut e = mapping(&[
            ("10.0.0.0/8", "10.0.0.0"),
            ("10.0.0.0/24", "10.0.0.255"),
        ]);
        e.remove(&net("10.0.0.0/8"));
        assert_eq!(
            ext_lsa_id_assignment(&e, net("10.0.0.0/24")).unwrap().0,
            addr("10.0.0.255")
        );
        let (id, rekeys) =
            ext_lsa_id_assignment(&e, net("10.0.0.0/16")).unwrap();
        assert_eq!(id, addr("10.0.0.0"));
        assert!(rekeys.is_empty());
    }

    #[test]
    fn host_route_cannot_be_displaced() {
        // A /32 occupying the network number cannot move to a
        // broadcast form (it is its own broadcast).
        let e = mapping(&[("10.0.0.0/32", "10.0.0.0")]);
        assert!(ext_lsa_id_assignment(&e, net("10.0.0.0/24")).is_none());
    }
}
