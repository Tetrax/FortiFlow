'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

let addressSelection = {};
try { addressSelection = require('../lib/address-selection'); } catch {}

function config(addresses = {}) {
  return { addresses };
}

function address(name, cidr, extra = {}) {
  return { name, cidr, ...extra };
}

test('returns containing FortiGate subnet objects in LPM order and no calculated subnet', () => {
  assert.equal(typeof addressSelection.buildAddressChoices, 'function');
  const choices = addressSelection.buildAddressChoices(
    ['10.0.0.20', '10.0.0.10'],
    config({
      BROAD: address('BROAD', '10.0.0.0/16'),
      EXACT: address('EXACT', '10.0.0.0/24'),
      FQDN: address('FQDN', null, { fqdn: 'servers.example.test' }),
    }),
  );

  assert.equal(choices.observedHostCount, 2);
  assert.deepEqual(choices.existingObjects.map(item => item.name), ['EXACT', 'BROAD']);
  assert.deepEqual(choices.existingObjects.map(item => item.cidr), ['10.0.0.0/24', '10.0.0.0/16']);
  assert.equal(choices.existingObjects[0].unobservedIpCount, 254);
  assert.equal(choices.calculatedSubnet, null);
  assert.deepEqual(choices.missingHosts, ['10.0.0.10', '10.0.0.20']);
});

test('calculates a minimal cover only when no existing object contains every observed IP', () => {
  const choices = addressSelection.buildAddressChoices(
    ['10.0.255.10', '10.0.0.10'],
    config({
      PARTIAL: address('PARTIAL', '10.0.0.0/24'),
      FQDN: address('FQDN', null, { fqdn: 'servers.example.test' }),
      RANGE: address('RANGE', null, { type: 'iprange', startInt: 0, endInt: 1 }),
    }),
  );

  assert.deepEqual(choices.existingObjects, []);
  assert.deepEqual(choices.calculatedSubnet, {
    cidr: '10.0.0.0/16',
    unobservedIpCount: 65534,
  });
});

test('uses arithmetic counts and does not enumerate the covered address space', () => {
  const choices = addressSelection.buildAddressChoices(
    ['10.10.10.10'],
    config({ HUGE: address('HUGE', '10.0.0.0/8') }),
  );
  assert.equal(choices.existingObjects[0].unobservedIpCount, 16777215);
  assert.equal(Object.keys(choices).includes('expandedIps'), false);
});

test('separates existing and missing /32 address objects', () => {
  const choices = addressSelection.buildAddressChoices(
    ['192.0.2.10', '192.0.2.11'],
    config({
      HOST_A: address('HOST_A', '192.0.2.10/32'),
      NETWORK: address('NETWORK', '192.0.2.0/24'),
    }),
  );
  assert.deepEqual(choices.existingHosts, [{ ip: '192.0.2.10', objectName: 'HOST_A' }]);
  assert.deepEqual(choices.missingHosts, ['192.0.2.11']);
});

test('does not use address names as technical containment evidence', () => {
  const choices = addressSelection.buildAddressChoices(
    ['203.0.113.10'],
    config({
      misleading: address('misleading', '203.0.113.0/24'),
      unrelated: address('203.0.113.10', '198.51.100.0/24'),
    }),
  );
  assert.deepEqual(choices.existingObjects.map(item => item.cidr), ['203.0.113.0/24']);
});

test('is deterministic regardless of observed input and object insertion order', () => {
  const first = addressSelection.buildAddressChoices(
    ['10.0.0.20', '10.0.0.10', '10.0.0.10'],
    config({ Z: address('Z', '10.0.0.0/16'), A: address('A', '10.0.0.0/24') }),
  );
  const second = addressSelection.buildAddressChoices(
    ['10.0.0.10', '10.0.0.20'],
    config({ A: address('A', '10.0.0.0/24'), Z: address('Z', '10.0.0.0/16') }),
  );
  assert.deepEqual(first, second);
});

test('validates confirmed existing-object, subnet and hosts selections statelessly', () => {
  const observed = ['10.0.0.10', '10.0.0.20'];
  const fortiConfig = config({ EXISTING: address('EXISTING', '10.0.0.0/24') });

  assert.equal(addressSelection.validateAddressSelection(
    observed,
    { mode: 'existing-object', objectName: 'EXISTING', confirmed: true },
    fortiConfig,
  ).ok, true);
  assert.equal(addressSelection.validateAddressSelection(
    observed,
    { mode: 'subnet', cidr: '10.0.0.0/27', confirmed: true },
    config(),
  ).ok, true);
  assert.equal(addressSelection.validateAddressSelection(
    observed,
    { mode: 'hosts', ips: ['10.0.0.10', '10.0.0.20'], confirmed: true },
    config(),
  ).ok, true);
});

test('rejects stale objects, excluded hosts and unconfirmed choices', () => {
  const observed = ['10.0.0.10', '10.0.0.20'];
  const fortiConfig = config({ EXISTING: address('EXISTING', '10.0.0.0/24') });

  const stale = addressSelection.validateAddressSelection(
    observed,
    { mode: 'existing-object', objectName: 'REMOVED', confirmed: true },
    fortiConfig,
  );
  assert.equal(stale.ok, false);
  assert.ok(stale.errors.some(error => /objet.*introuvable/i.test(error)));

  const excluded = addressSelection.validateAddressSelection(
    observed,
    { mode: 'subnet', cidr: '10.0.0.0/28', confirmed: true },
    config(),
  );
  assert.equal(excluded.ok, false);
  assert.ok(excluded.errors.some(error => /contient pas/i.test(error)));

  const unconfirmed = addressSelection.validateAddressSelection(
    observed,
    { mode: 'hosts', ips: ['10.0.0.10', '10.0.0.20'], confirmed: false },
    config(),
  );
  assert.equal(unconfirmed.ok, false);
  assert.ok(unconfirmed.errors.some(error => /confirmation/i.test(error)));
});

test('rejects invalid observed IPs and selections instead of guessing', () => {
  assert.throws(
    () => addressSelection.buildAddressChoices(['10.0.0.999'], config()),
    /IPv4|invalide/i,
  );
  const result = addressSelection.validateAddressSelection(
    ['10.0.0.10'],
    { mode: 'hosts', ips: ['10.0.0.11'], confirmed: true },
    config(),
  );
  assert.equal(result.ok, false);
  assert.ok(result.errors.some(error => /observ/i.test(error)));
});
