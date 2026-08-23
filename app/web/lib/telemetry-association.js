'use strict';

const {
  collectTelemetryIdentity,
  normalizeConfigIdentity,
  validateConfigTelemetryConsistency,
} = require('./config-consistency');

const ASSOCIATION_MATCHED = 'matched';
const ASSOCIATION_CONFIRMATION_REQUIRED = 'confirmation_required';
const ASSOCIATION_SELECTION_REQUIRED = 'selection_required';
const ASSOCIATION_CONTRADICTION = 'contradiction';
const CONFIG_TELEMETRY_ASSOCIATION_REQUIRED = 'CONFIG_TELEMETRY_ASSOCIATION_REQUIRED';
const CONFIG_TELEMETRY_DEVICE_SELECTION_REQUIRED = 'CONFIG_TELEMETRY_DEVICE_SELECTION_REQUIRED';
const CONFIG_TELEMETRY_MISMATCH = 'CONFIG_TELEMETRY_MISMATCH';

function createConfirmedTelemetryAssociation({
  telemetryDeviceName,
  configHostname,
  telemetryContextId,
  configContextId,
  confirmedAt = new Date().toISOString(),
}) {
  return {
    telemetryDeviceName,
    configHostname,
    telemetryContextId,
    configContextId,
    confirmedByUser: true,
    confirmedAt,
  };
}

function createSelectedTelemetryAssociation({
  telemetryDeviceName,
  configHostname,
  telemetryContextId,
  configContextId,
}) {
  return {
    telemetryDeviceName,
    configHostname,
    telemetryContextId,
    configContextId,
    selectedByUser: true,
    confirmedByUser: false,
    confirmedAt: null,
  };
}

function isTelemetryAssociationUsable(association, context = {}) {
  return Boolean(
    (association?.confirmedByUser || association?.selectedByUser)
      && association.telemetryDeviceName
      && (association.confirmedByUser ? association.configHostname : true)
      && association.telemetryContextId === context.telemetryContextId
      && association.configContextId === context.configContextId
      && (context.telemetryDeviceName === undefined || association.telemetryDeviceName === context.telemetryDeviceName)
      && (context.configHostname === undefined || association.configHostname === context.configHostname),
  );
}

function refuseTelemetryConfigAssociation() {
  return {
    status: 'unassociated',
    code: 'CONFIG_TELEMETRY_ASSOCIATION_REFUSED',
    association: null,
  };
}

function evaluateTelemetryConfigAssociation(flows, fortiConfig = {}, context = {}, existingAssociation = null) {
  const telemetryIdentity = collectTelemetryIdentity(flows);
  const configIdentity = normalizeConfigIdentity(fortiConfig);
  const telemetryDeviceNames = telemetryIdentity.devnames;
  const selected = existingAssociation?.telemetryDeviceName || context.telemetryDeviceName || null;
  const telemetryDeviceName = selected || (telemetryDeviceNames.length === 1 ? telemetryDeviceNames[0] : null);
  const scopedFlows = selected
    ? (Array.isArray(flows) ? flows : []).filter(flow => {
      const scope = flow?.scope && typeof flow.scope === 'object' ? flow.scope : {};
      return String(flow?.devname || scope.devname || '').trim() === selected;
    })
    : flows;
  const validation = validateConfigTelemetryConsistency(scopedFlows, fortiConfig);
  const base = {
    telemetryDeviceNames,
    telemetryDeviceName,
    configHostname: configIdentity.hostname,
    telemetryContextId: context.telemetryContextId || null,
    configContextId: context.configContextId || null,
    validation,
  };

  if (telemetryDeviceNames.length > 1 && !selected) {
    return {
      ...base,
      status: ASSOCIATION_SELECTION_REQUIRED,
      code: CONFIG_TELEMETRY_DEVICE_SELECTION_REQUIRED,
      requiresConfirmation: true,
    };
  }
  if (selected && !telemetryDeviceNames.includes(selected)) {
    return {
      ...base,
      status: ASSOCIATION_CONTRADICTION,
      code: CONFIG_TELEMETRY_MISMATCH,
      requiresConfirmation: false,
    };
  }
  if (configIdentity.hostname && telemetryDeviceName && configIdentity.hostname !== telemetryDeviceName) {
    const hostnameMismatch = `hostname config=${configIdentity.hostname}; télémétrie=${telemetryDeviceName}`;
    const confirmationSuppliesOnlyMissingProof = 'aucune preuve positive d’identité ou de correspondance interface-réseau';
    const confirmableNameMismatch = validation.errors.length > 0
      && validation.errors.every(error => (error.details || []).every(detail =>
        detail === hostnameMismatch || detail === confirmationSuppliesOnlyMissingProof
      ));
    if (validation.errors.length > 0 && !confirmableNameMismatch) {
      return {
        ...base,
        status: ASSOCIATION_CONTRADICTION,
        code: CONFIG_TELEMETRY_MISMATCH,
        requiresConfirmation: false,
      };
    }
    if (existingAssociation?.confirmedByUser
        && isTelemetryAssociationUsable(existingAssociation, {
          ...context,
          telemetryDeviceName,
          configHostname: configIdentity.hostname,
        })) {
      if (confirmableNameMismatch) base.validation = { ...validation, ok: true, errors: [], message: null };
      return {
        ...base,
        status: ASSOCIATION_MATCHED,
        requiresConfirmation: false,
        confirmedByUser: true,
      };
    }
    if (confirmableNameMismatch) {
      base.validation = { ...validation, ok: true, errors: [], message: null };
    }
    return {
      ...base,
      status: ASSOCIATION_CONFIRMATION_REQUIRED,
      code: CONFIG_TELEMETRY_ASSOCIATION_REQUIRED,
      requiresConfirmation: true,
    };
  }
  if (!validation.ok) {
    return {
      ...base,
      status: ASSOCIATION_CONTRADICTION,
      code: CONFIG_TELEMETRY_MISMATCH,
      requiresConfirmation: false,
    };
  }
  return {
    ...base,
    status: ASSOCIATION_MATCHED,
    requiresConfirmation: false,
  };
}

module.exports = {
  ASSOCIATION_MATCHED,
  ASSOCIATION_CONFIRMATION_REQUIRED,
  ASSOCIATION_SELECTION_REQUIRED,
  ASSOCIATION_CONTRADICTION,
  CONFIG_TELEMETRY_ASSOCIATION_REQUIRED,
  CONFIG_TELEMETRY_DEVICE_SELECTION_REQUIRED,
  CONFIG_TELEMETRY_MISMATCH,
  createConfirmedTelemetryAssociation,
  createSelectedTelemetryAssociation,
  isTelemetryAssociationUsable,
  refuseTelemetryConfigAssociation,
  evaluateTelemetryConfigAssociation,
};
