//
// Copyright (c) The Holo Core Contributors
//
// SPDX-License-Identifier: MIT
//

use holo_utils::ip::IpNetworkKind;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::{
    AddressFlags, AddressMsg, InterfaceUpdateMsg, RouteKeyMsg, RouteMsg,
};

use crate::ibus;
use crate::instance::{Instance, InstanceUpView};
use crate::interface::Interface;
use crate::route::{Metric, Route, RouteType};
use crate::version::Version;

// ===== global functions =====

pub(crate) fn process_iface_update<V>(
    instance: &mut Instance<V>,
    msg: InterfaceUpdateMsg,
) where
    V: Version,
{
    // Lookup interface.
    let Some((iface_idx, iface)) = instance
        .interfaces
        .update_ifindex(&msg.ifname, Some(msg.ifindex))
    else {
        return;
    };

    // Update interface data.
    iface.system.mtu = Some(msg.mtu);
    iface.system.flags = msg.flags;

    if let Some((mut instance, interfaces)) = instance.as_up() {
        let iface = &mut interfaces[iface_idx];

        // Check if RIP needs to be activated or deactivated on this interface.
        iface.update(&mut instance);

        // Add connected routes.
        if iface.state.active {
            for addr in &iface.system.addr_list {
                connected_route_add(&mut instance, iface, addr);
            }
        }
    }
}

pub(crate) fn process_addr_add<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, iface)) =
        instance.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };

    // Ignore IPv4 unnumbered addresses.
    if msg.flags.contains(AddressFlags::UNNUMBERED) {
        return;
    }

    // Add address.
    if !iface.system.addr_list.insert(addr) {
        return;
    }

    if let Some((mut instance, interfaces)) = instance.as_up() {
        let iface = &mut interfaces[iface_idx];

        // Check if RIP needs to be activated on this interface.
        iface.update(&mut instance);

        // Add connected route.
        connected_route_add(&mut instance, iface, &addr);
    }
}

pub(crate) fn process_addr_del<V>(instance: &mut Instance<V>, msg: AddressMsg)
where
    V: Version,
{
    let Some(addr) = V::IpNetwork::get(msg.addr) else {
        return;
    };

    // Lookup interface.
    let Some((iface_idx, iface)) =
        instance.interfaces.get_mut_by_name(&msg.ifname)
    else {
        return;
    };

    // Ignore IPv4 unnumbered addresses.
    if msg.flags.contains(AddressFlags::UNNUMBERED) {
        return;
    }

    // Remove address.
    if !iface.system.addr_list.remove(&addr) {
        return;
    }

    if let Some((mut instance, interfaces)) = instance.as_up() {
        let iface = &mut interfaces[iface_idx];

        // Invalidate connected route.
        connected_route_invalidate(&mut instance, iface, &addr);

        // Check if RIP needs to be deactivated on this interface.
        iface.update(&mut instance);
    }
}

// ===== route redistribution =====

// A route was added (or updated) in the default RIB by a redistributed
// protocol: install it in the RIP routing table so that it gets
// advertised in the next Response.
pub(crate) fn process_redistribute_add<V>(
    instance: &mut Instance<V>,
    msg: RouteMsg,
) where
    V: Version,
{
    // Ignore prefixes that don't match the instance address-family.
    let Some(prefix) = V::IpNetwork::get(msg.prefix) else {
        return;
    };

    // Ignore routes whose source protocol is not being redistributed.
    let Some(cfg) = instance.config.redistribution.get(&msg.protocol).cloned()
    else {
        return;
    };

    let Some((instance, _)) = instance.as_up() else {
        return;
    };

    // Keep the redistributed candidate in its own store. A route the
    // protocol actually learned (or a connected route) always wins
    // over an imported copy: the candidate only projects into the
    // route table when nothing better occupies the prefix.
    let keep_existing = instance
        .state
        .routes
        .get(&prefix)
        .is_some_and(|route| route.route_type != RouteType::Redistributed);
    instance.state.redistributed.insert(prefix, msg.protocol);
    if keep_existing {
        return;
    }

    // Redistributed routes have no outgoing interface (ifindex 0), so
    // they are advertised on every active interface and are never
    // affected by split-horizon or interface-stop invalidation.
    let route = Route::new(
        prefix,
        0,
        None,
        Metric::from(cfg.metric),
        0,
        RouteType::Redistributed,
        &instance.config.trace_opts,
    );
    instance.state.routes.insert(prefix, route);

    // Signal the output process to trigger an update.
    instance.tx.protocol_input.trigger_update();
}

// A redistributed route was deleted from the default RIB: poison it
// (metric infinite) and start its flush timer.
pub(crate) fn process_redistribute_del<V>(
    instance: &mut Instance<V>,
    msg: RouteKeyMsg,
) where
    V: Version,
{
    let Some(prefix) = V::IpNetwork::get(msg.prefix) else {
        return;
    };

    let Some((instance, _)) = instance.as_up() else {
        return;
    };

    if instance.state.redistributed.remove(&prefix).is_none() {
        return;
    }
    // Only poison when the redistributed candidate was the active
    // route; a learned route behind it stays untouched and becomes
    // (and remains) the projection.
    if let Some(route) = instance.state.routes.get_mut(&prefix)
        && route.route_type == RouteType::Redistributed
    {
        route.invalidate(
            instance.config.flush_interval,
            instance.tx,
            &instance.config.trace_opts,
        );
    }
}

// A protocol is not redistributed anymore: poison all of its routes.
pub(crate) fn redistribute_delete_protocol<V>(
    instance: &mut Instance<V>,
    protocol: Protocol,
) where
    V: Version,
{
    let Some((instance, _)) = instance.as_up() else {
        return;
    };

    let prefixes: Vec<V::IpNetwork> = instance
        .state
        .redistributed
        .iter()
        .filter(|(_, p)| **p == protocol)
        .map(|(prefix, _)| *prefix)
        .collect();
    for prefix in prefixes {
        instance.state.redistributed.remove(&prefix);
        if let Some(route) = instance.state.routes.get_mut(&prefix)
            && route.route_type == RouteType::Redistributed
        {
            route.invalidate(
                instance.config.flush_interval,
                instance.tx,
                &instance.config.trace_opts,
            );
        }
    }
}

// The metric of a redistributed protocol changed: update its routes.
pub(crate) fn redistribute_update_protocol<V>(
    instance: &mut Instance<V>,
    protocol: Protocol,
) where
    V: Version,
{
    let Some(cfg) = instance.config.redistribution.get(&protocol).cloned()
    else {
        return;
    };
    let Some((instance, _)) = instance.as_up() else {
        return;
    };

    let metric = Metric::from(cfg.metric);
    let prefixes: Vec<V::IpNetwork> = instance
        .state
        .redistributed
        .iter()
        .filter(|(_, p)| **p == protocol)
        .map(|(prefix, _)| *prefix)
        .collect();
    for prefix in prefixes {
        if let Some(route) = instance.state.routes.get_mut(&prefix)
            && route.route_type == RouteType::Redistributed
            && !route.metric.is_infinite()
        {
            route.metric = metric;
            route.flags.insert(crate::route::RouteFlags::CHANGED);
        }
    }
    instance.tx.protocol_input.trigger_update();
}

// ===== helper functions =====

fn connected_route_add<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &Interface<V>,
    addr: &V::IpNetwork,
) where
    V: Version,
{
    if !addr.is_routable() {
        return;
    }

    // Uninstall previously learned route (if any).
    let prefix = addr.apply_mask();
    if let Some(route) = instance.state.routes.get(&prefix) {
        ibus::tx::route_uninstall(&instance.tx.ibus, route);
    }

    // Add new connected route.
    let route = Route::new(
        prefix,
        iface.system.ifindex.unwrap(),
        None,
        iface.config.cost,
        0,
        RouteType::Connected,
        &instance.config.trace_opts,
    );
    instance.state.routes.insert(prefix, route);

    // Signal the output process to trigger an update.
    instance.tx.protocol_input.trigger_update();
}

fn connected_route_invalidate<V>(
    instance: &mut InstanceUpView<'_, V>,
    iface: &Interface<V>,
    addr: &V::IpNetwork,
) where
    V: Version,
{
    if !addr.is_routable() {
        return;
    }

    let prefix = addr.apply_mask();
    if let Some(route) = instance.state.routes.get_mut(&prefix) {
        route.invalidate(
            iface.config.flush_interval,
            instance.tx,
            &instance.config.trace_opts,
        );
    }
}
