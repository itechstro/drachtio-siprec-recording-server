/**
 * Call comes in and its a SIPREC call (multi-part content)
 * Parse the payload into two sdps
 * Creeate a uuid and store the uniused sdp by uuid
 * Srf#createB2BUA where localSdpA is the SDP we will use first,
 * and localSdpB is a function that pulls the sdp back out of redis
 * and creates a multipart SDP
 * Now, when the other INVITE comes in from freeswwitch
 * we pull the unused SDP out of redis and stick the one FS is offering back in there
 * we send 200 OK with the unused SDP and we are done
 */
const config = require('config');
const payloadParser = require('./payload-parser');
const transform = require('sdp-transform');

const activeCalls = new Map();

// ---- Per-recorder configuration (from local.json via node-config) ----
// Falls back to the original ibratro values if a key is missing, so a
// recorder with an incomplete local.json degrades instead of crashing.
function cfg(key, fallback) {
  return config.has(key) ? config.get(key) : fallback;
}
const FS_ADDRESS   = cfg('recorder.fsAddress', '10.100.0.30');
const FS_PORT      = cfg('recorder.fsPort', 5060);
const FS_USER      = cfg('recorder.fsUser', 'recorder');
const FS_PUBLIC_IP = cfg('recorder.fsPublicIp', '213.35.127.143');
const FS_AUTH_USER = cfg('recorder.fsAuthUser', '');
const FS_AUTH_PASS = cfg('recorder.fsAuthPassword', '');
const FS_AUTH_READY = Boolean(
  FS_AUTH_USER &&
  FS_AUTH_PASS &&
  FS_AUTH_PASS !== 'CHANGE_ME'
);

function resolveFsDomain() {
  if (config.has('recorder.fsDomain')) return config.get('recorder.fsDomain');
  if (config.has('freeswitch')) {
    const domains = config.get('freeswitch');
    if (Array.isArray(domains) && domains.length > 0 && domains[0]) return domains[0];
  }
  return FS_ADDRESS;
}

// Request-URI uses the FusionPBX domain. INVITE is sent to fsAddress via proxy.
// Digest auth as a domain extension makes FS use that domain's dialplan context
// (user_context) so no public recorder_catch_* transfer is required.
const FS_DOMAIN = resolveFsDomain();
const FS_URI    = `sip:${FS_USER}@${FS_DOMAIN}`;
const FS_PROXY  = `sip:${FS_ADDRESS}:${FS_PORT}`;
const FS_CALLEE = FS_USER;
const FS_AUTH   = FS_AUTH_READY
  ? { username: FS_AUTH_USER, password: FS_AUTH_PASS }
  : null;

function buildFsInviteOpts({
  localSdp, agentExt, agentName, calleeExt, calleeName,
  roomName, primaryId, streamId, isNewCall
}) {
  const authUser = FS_AUTH ? FS_AUTH_USER : agentExt;
  const fromUri = `"${agentName}" <sip:${authUser}@${FS_DOMAIN}>`;
  const opts = {
    proxy: FS_PROXY,
    localSdp,
    callingNumber: authUser,
    callingName: agentName,
    calledNumber: FS_CALLEE,
    headers: {
      from: fromUri,
      contact: `<sip:${authUser}@${FS_DOMAIN}>`,
      'X-Room-Name': roomName,
      'X-Stream-ID': streamId,
      'X-Primary-Session': primaryId,
      'X-Is-New-Call': isNewCall,
      'X-Original-Dialed': calleeExt,
      'X-Caller-Name': agentName,
      'X-Callee-Name': calleeName
    }
  };
  if (FS_AUTH) opts.auth = FS_AUTH;
  return opts;
}

function normalizeStreamSdp(sdp) {
  return sdp.replace(/a=inactive/g, 'a=sendrecv').replace(/a=sendonly/g, 'a=sendrecv');
}

function buildFinalSdp(sessionSdp, uac1, uac2, fsPublicIp) {
  const mitelSdp = transform.parse(sessionSdp);
  const fsSdp1 = transform.parse(uac1.remote.sdp);
  const fsSdp2 = transform.parse(uac2.remote.sdp);

  mitelSdp.connection = { version: 4, ip: fsPublicIp };

  fsSdp1.media[0].direction = 'recvonly';
  if (fsSdp1.media[0].connection) fsSdp1.media[0].connection.ip = fsPublicIp;
  else fsSdp1.media[0].connection = { version: 4, ip: fsPublicIp };

  fsSdp2.media[0].direction = 'recvonly';
  if (fsSdp2.media[0].connection) fsSdp2.media[0].connection.ip = fsPublicIp;
  else fsSdp2.media[0].connection = { version: 4, ip: fsPublicIp };

  mitelSdp.media = [fsSdp1.media[0], fsSdp2.media[0]];
  return transform.write(mitelSdp);
}

function attachMitelModifyHandler(uas, callData, logger, callKey) {
  uas.on('modify', (req, res) => handleMitelModify(req, res, callData, logger, callKey));
}

async function propagateMediaToFs(callData, parsedOpts, logger, callKey) {
  if (!callData.uac1 || !callData.uac2) return callData.finalSdp;

  const sdp1 = normalizeStreamSdp(parsedOpts.sdp1);
  const sdp2 = normalizeStreamSdp(parsedOpts.sdp2);

  await Promise.all([
    callData.uac1.modify(sdp1),
    callData.uac2.modify(sdp2)
  ]);

  const finalSdp = buildFinalSdp(parsedOpts.sdp1, callData.uac1, callData.uac2, FS_PUBLIC_IP);
  callData.finalSdp = finalSdp;
  logger.info({callKey}, 'Propagated updated SIPREC media to FreeSWITCH legs');
  return finalSdp;
}

async function handleMitelModify(req, res, callData, logger, callKey) {
  const modifyLogger = logger.child({callKey, reinvite: true});
  try {
    if (!callData.uac1 || !callData.uac2) {
      modifyLogger.warn('SIPREC re-INVITE before FS legs ready; echoing cached SDP');
      return res.send(200, { body: callData.finalSdp });
    }

    modifyLogger.info('Received SIPREC re-INVITE');
    const parsedOpts = await payloadParser({ req, res, logger: modifyLogger });
    const finalSdp = await propagateMediaToFs(callData, parsedOpts, modifyLogger, callKey);
    res.send(200, { body: finalSdp });
  } catch (err) {
    modifyLogger.error(err, 'Failed to propagate SIPREC re-INVITE to FreeSWITCH');
    res.send(488);
  }
}

module.exports = (logger) => {
  return handler;
};

const handler = (req, res) => {
  const callid = req.get('Call-ID');
  const logger = req.srf.locals.logger.child({callid});
  const opts = {req, res, logger};
  const ctype = req.get('Content-Type') || '';

  if (ctype.includes('multipart/mixed')) {
    handleIncomingSiprecInvite(req, res, opts);
  } else {
    res.send(488);
  }
};

async function handleIncomingSiprecInvite(req, res, opts) {
  const srf = req.srf;

  // SYNCHRONOUS EXTRACTION: must run before any await so two near-simultaneous
  // SIPREC INVITEs for the same call are serialised by the event loop and only
  // the first is flagged as the new call.
  const fromHeader = req.getParsedHeader('From');
  const fromUser = (fromHeader && fromHeader.uri && fromHeader.uri.user) ? fromHeader.uri.user : 'unknown';

  // PER-CALL KEY: Mitel sends two SIPREC INVITEs per call. sipSessionID is stable
  // across both; <session session_id> can differ per INVITE if parsed incorrectly.
  let callKey = req.get('Call-ID');
  try {
    const ss = /<sipSessionID>([^<]+)</i.exec(req.body);
    if (ss && ss[1] && ss[1].trim()) {
      callKey = ss[1].split(';')[0].trim();
    } else {
      const sm = /<session[^>]*\ssession_id="([^"]+)"/i.exec(req.body);
      if (sm && sm[1] && sm[1].trim()) callKey = sm[1].trim();
    }
  } catch (e) {
    opts.logger.error('Failed to derive session_id from metadata; using Call-ID');
  }
  opts.logger.info({callKey}, 'SIPREC call key derived');

  // Agent extension from the first participant aor (e.g. sip:1010@...). Used
  // only for CDR caller fields and the record-file prefix, NOT for grouping.
  let agentAor = fromUser;
  try {
    const am = /aor="sip:([^@"]+)@/i.exec(req.body);
    if (am && am[1] && am[1].trim()) agentAor = am[1].trim();
  } catch (e) {
    opts.logger.error('Failed to derive agent aor from metadata; using From user');
  }

  let isNewCall = 'false';
  let primaryId = callKey;

  // Mitel may use different session IDs on each SIPREC INVITE. Merge into an
  // in-progress call for the same agent so we do not open a second conference.
  if (!activeCalls.has(callKey)) {
    for (const [existingKey, existingData] of activeCalls.entries()) {
      if (existingData.agentAor === agentAor &&
          (existingData.pendingSetup || existingData.fsLegsActive || existingData.established) &&
          Date.now() - existingData.startedAt < 60000) {
        opts.logger.info({callKey, existingKey, agentAor}, 'Merging SIPREC INVITE into active call by agent');
        callKey = existingKey;
        break;
      }
    }
  }

  if (!activeCalls.has(callKey)) {
    activeCalls.set(callKey, {
      primaryId: primaryId,
      agentAor: agentAor,
      startedAt: Date.now(),
      pendingSetup: true,
      streams: new Set(),
      timeout: null,
      established: false,
      fsLegsActive: false,
      finalSdp: null,
      uac1: null,
      uac2: null,
      uasDialogs: [],
      dialogCount: 0,
      teardownScheduled: false,
      settingUpFs: false
    });
    isNewCall = 'true';
  } else {
    primaryId = activeCalls.get(callKey).primaryId;
    isNewCall = 'false';
    if (activeCalls.get(callKey).timeout) {
      clearTimeout(activeCalls.get(callKey).timeout);
      activeCalls.get(callKey).timeout = null;
    }
  }

  let parsedOpts = null;
  try {
    parsedOpts = await payloadParser(opts);
    const callData = activeCalls.get(callKey);

    // Mitel sends a second SIPREC INVITE for the same session_id. Answer it
    // locally; do not open another pair of FS legs (that duplicates recording).
    if (callData.fsLegsActive || callData.established) {
      if (!callData.finalSdp) {
        opts.logger.warn({callKey}, 'Follow-up SIPREC INVITE while FS setup in progress; rejecting');
        return res.send(480);
      }
      opts.logger.info(
        {callKey, sessionId: parsedOpts.sessionId},
        'Answering follow-up SIPREC INVITE without new FS legs'
      );
      // Mitel sends a second SIPREC INVITE (not a re-INVITE) when media changes
      // at answer. Push the updated SDPs to the existing FS legs before answering.
      await propagateMediaToFs(callData, parsedOpts, opts.logger, callKey);
      const uas = await srf.createUAS(req, res, { localSdp: callData.finalSdp });
      callData.uasDialogs.push(uas);
      callData.dialogCount++;
      attachMitelModifyHandler(uas, callData, opts.logger, callKey);
      uas.on('destroy', () => releaseDialog(opts, callKey));
      return;
    }
    if (callData.settingUpFs) {
      opts.logger.warn({callKey}, 'Parallel SIPREC INVITE while FS setup in progress; rejecting');
      return res.send(480);
    }
    callData.settingUpFs = true;

    // One logical session per callKey — not one uuid per INVITE.
    callData.streams.add(callKey);

    const fsUri = FS_URI;

    const agentExt = (parsedOpts.caller && parsedOpts.caller.number) ? parsedOpts.caller.number : agentAor;
    // Per-call conference room: agent-prefixed (keeps recordings grouped/looked
    // up under the agent) but suffixed with the per-call id so that two
    // OVERLAPPING calls for the same agent land in separate conferences instead
    // of mixing into one. Both streams of a call share primaryId, so they still
    // join the same room and mix correctly.
    const roomName = `${agentExt}-${primaryId}`;
    const calleeExt = (parsedOpts.callee && parsedOpts.callee.number) ? parsedOpts.callee.number : 'unknown';

    // Contact names for FreeSWITCH CDRs. Mitel's metadata carries identities
    // as <nameID aor="sip:USER@..."> (no <name> elements), so derive the
    // display names from the participant aor list, agent first.
    let agentName = agentExt;
    let calleeName = calleeExt;
    try {
      const users = [];
      const regex = /aor="sip:([^@"]+)@/gi;
      let match;
      while ((match = regex.exec(req.body)) !== null) {
        users.push(match[1]);
      }
      if (users.length > 0) agentName = users[0];
      if (users.length > 1) calleeName = users[1];
    } catch (e) {
      opts.logger.error('Failed to parse participant aors from XML');
    }

    // Force sendrecv so FreeSWITCH transmits RTP back to the MBG
    const sdp1 = normalizeStreamSdp(parsedOpts.sdp1);
    const sdp2 = normalizeStreamSdp(parsedOpts.sdp2);

    if (!FS_AUTH) {
      opts.logger.warn(
        {fsDomain: FS_DOMAIN, fsUser: FS_USER},
        'recorder.fsAuthUser/fsAuthPassword not set; FS will use public context ' +
        '(requires recorder_catch_* transfer). Set domain extension auth to skip it.'
      );
    }

    // Sequential legs: stream 1 joins the conference first (no recording).
    // Stream 2 joins second; FSPBX dialplan keys recording/CDR off X-Stream-ID=2.
    // Digest auth as a domain extension puts both legs in FS_DOMAIN context.
    const uac1 = await srf.createUAC(fsUri, buildFsInviteOpts({
      localSdp: sdp1,
      agentExt,
      agentName,
      calleeExt,
      calleeName,
      roomName,
      primaryId,
      streamId: '1',
      isNewCall
    }));

    callData.fsLegsActive = true;

    const uac2 = await srf.createUAC(fsUri, buildFsInviteOpts({
      localSdp: sdp2,
      agentExt,
      agentName,
      calleeExt,
      calleeName,
      roomName,
      primaryId,
      streamId: '2',
      isNewCall: 'false'
    }));

    const finalSdp = buildFinalSdp(parsedOpts.sdp1, uac1, uac2, FS_PUBLIC_IP);

    const uas = await srf.createUAS(req, res, {
      localSdp: finalSdp
    });

    callData.established = true;
    callData.pendingSetup = false;
    callData.settingUpFs = false;
    callData.finalSdp = finalSdp;
    callData.uac1 = uac1;
    callData.uac2 = uac2;
    callData.uasDialogs.push(uas);
    callData.dialogCount++;

    attachMitelModifyHandler(uas, callData, opts.logger, callKey);
    uas.on('destroy', () => releaseDialog(opts, callKey));

  } catch (err) {
    opts.logger.error(err, 'Error pushing SIPREC streams to FreeSWITCH');
    // Roll back the map entry: a failed setup must not leave the call key
    // wedged in the Map, or the retried/!next INVITE reads isNewCall=false.
    if (activeCalls.has(callKey)) {
      const callData = activeCalls.get(callKey);
      callData.streams.delete(callKey);
      callData.pendingSetup = false;
      callData.settingUpFs = false;
      if (callData.streams.size === 0 && !callData.fsLegsActive) {
        if (callData.timeout) clearTimeout(callData.timeout);
        activeCalls.delete(callKey);
      }
    }
    if (!res.headersSent) res.send(480);
  }
}

function releaseDialog(opts, callKey) {
  const callData = activeCalls.get(callKey);
  if (!callData) return;
  callData.dialogCount--;
  opts.logger.info({callKey, dialogCount: callData.dialogCount}, 'SIPREC dialog ended');
  if (callData.dialogCount <= 0) {
    teardownFsLegs(opts, callKey);
  }
}

function teardownFsLegs(opts, callKey) {
  const callData = activeCalls.get(callKey);
  if (!callData || callData.teardownScheduled) return;
  callData.teardownScheduled = true;
  if (callData.timeout) clearTimeout(callData.timeout);
  // End FS conference legs immediately so recording duration matches the call.
  if (callData.uac1) { try { callData.uac1.destroy(); } catch (e) { /* */ } }
  if (callData.uac2) { try { callData.uac2.destroy(); } catch (e) { /* */ } }
  activeCalls.delete(callKey);
}
