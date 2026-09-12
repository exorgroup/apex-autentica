/**
 * Copyright EXOR Group ltd 2025
 * APEX Laravel Autentica Authentication System
 * Description: Vue composable over can.js, reading the maps Autentica shares into Inertia page
 *              props. A thin wrapper only — all the logic lives in the framework-free core.
 * URL: exorgroup/apex-autentica/resources/js/useCan.js
 */

import { computed } from 'vue';
import { usePage } from '@inertiajs/vue3';
import { can as rawCan, canAny as rawCanAny, canCustom as rawCanCustom } from './can.js';

/**
 * Permission checks bound to the current Inertia page.
 *
 * Requires the host application to share the maps, which the server side builds:
 *
 *   'auth' => [
 *       'user' => $request->user(),
 *       ...\Apex\Autentica\Core\Support\PermissionMap::for($request->user()),
 *   ]
 *
 * Usage:
 *   const { can, canAny, canCustom } = useCan();
 *   can('events', 'update');            // one action
 *   can('events', ['read', 'update']);  // all of them
 *   canAny('events', ['update', 'delete']);
 *   canCustom('events', 'approve_hero');
 *
 * @returns {{
 *   can: (resource: string, actions: string|string[]) => boolean,
 *   canAny: (resource: string, actions: string[]) => boolean,
 *   canCustom: (resource: string, key: string) => boolean,
 *   permissions: import('vue').ComputedRef<object>,
 *   customPermissions: import('vue').ComputedRef<object>,
 * }}
 */
export function useCan() {
  const page = usePage();

  // Empty PHP arrays serialise to [], so default defensively rather than assuming an object.
  const permissions = computed(() => page.props?.auth?.can || {});
  const customPermissions = computed(() => page.props?.auth?.canCustom || {});

  return {
    can: (resource, actions) => rawCan(permissions.value, resource, actions),
    canAny: (resource, actions) => rawCanAny(permissions.value, resource, actions),
    canCustom: (resource, key) => rawCanCustom(customPermissions.value, resource, key),
    permissions,
    customPermissions,
  };
}
