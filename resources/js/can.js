/**
 * Copyright EXOR Group ltd 2025
 * APEX Laravel Autentica Authentication System
 * Description: Framework-free permission checks. No imports, no framework, no build step —
 *              usable from Vue, React, Svelte, a Blade sprinkle or plain script.
 * URL: exorgroup/apex-autentica/resources/js/can.js
 */

/**
 * Action name -> the letter used in the wire format.
 * Mirrors PermissionMap::ACTIONS on the PHP side. Keep the two in step.
 */
export const ACTIONS = {
  create: 'c',
  read: 'r',
  update: 'u',
  delete: 'd',
  print: 'p',
  history: 'h',
};

/**
 * Normalise an action to its single letter.
 * Accepts a full name ('update'), a letter ('u'), or any case.
 *
 * @param {string} action
 * @returns {string|null} The letter, or null if unrecognised.
 */
export function toLetter(action) {
  if (typeof action !== 'string' || action === '') return null;
  const key = action.toLowerCase();
  if (ACTIONS[key]) return ACTIONS[key];
  // Already a letter?
  return Object.values(ACTIONS).includes(key) ? key : null;
}

/**
 * May the holder of this map perform ALL of the given actions on a resource?
 *
 * An unknown resource, an unknown action, or a missing map all deny — never assume
 * permission that the server did not send.
 *
 * @param {object} map        The auth.can map, e.g. { events: 'cru' }
 * @param {string} resource   Resource identifier, e.g. 'events'
 * @param {string|string[]} actions One action or several; several means ALL of them.
 * @returns {boolean}
 */
export function can(map, resource, actions) {
  if (!map || typeof map !== 'object') return false;

  const letters = map[resource];
  if (typeof letters !== 'string' || letters === '') return false;

  const list = Array.isArray(actions) ? actions : [actions];
  if (list.length === 0) return false;

  return list.every((action) => {
    const letter = toLetter(action);
    return letter !== null && letters.includes(letter);
  });
}

/**
 * May the holder perform ANY of the given actions on a resource?
 *
 * @param {object} map
 * @param {string} resource
 * @param {string[]} actions
 * @returns {boolean}
 */
export function canAny(map, resource, actions) {
  const list = Array.isArray(actions) ? actions : [actions];
  return list.some((action) => can(map, resource, action));
}

/**
 * Does the holder have a named custom permission on a resource?
 *
 * @param {object} customMap The auth.canCustom map, e.g. { events: ['approve_hero'] }
 * @param {string} resource
 * @param {string} key       The custom permission name
 * @returns {boolean}
 */
export function canCustom(customMap, resource, key) {
  if (!customMap || typeof customMap !== 'object') return false;
  const list = customMap[resource];
  return Array.isArray(list) && list.includes(key);
}
