/**
 * Copyright EXOR Group ltd 2025
 * APEX Laravel Autentica Authentication System
 * Description: Entry point for Autentica's JavaScript. Ships inside the Composer package so the
 *              PHP that produces the permission maps and the JS that reads them stay version-locked.
 * URL: exorgroup/apex-autentica/resources/js/index.js
 */

// Framework-free core — safe to import anywhere, including outside Vue.
export { can, canAny, canCustom, toLetter, ACTIONS } from './can.js';

// Vue + Inertia binding. Importing this pulls in vue and @inertiajs/vue3, so import from
// './can.js' directly if you are not on that stack.
export { useCan } from './useCan.js';
