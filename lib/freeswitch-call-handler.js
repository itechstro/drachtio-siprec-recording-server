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

// Mitel often sends two SIPREC INVITEs for one internal call (one per setside)
// within a few hundred ms. Answering the second with the first session's FS RTP
// ports causes media collision and near-silent / one-sided recordings.
const DUPLICATE_SETSIDE_WINDOW_MS = 2000;

// ---- Per-recorder configuration (from local.json via node-config) ----
// Falls back to the original ibratro values if a key is missing, so a
// recorder with an incomplete local.json degrades instead of crashing.
function cfg(key, fallback) {
  return config.has(key) ? config.get(key) : fallback;
}

function extractParticipantUsers(body) {
  const users = [];
  const regex = /aor="sip:([^@"]+)@/gi;
  let match;
  while ((match = regex.exec(body)) !== null) {
    if (match[1] && !users.includes(match[1])) users.push(match[1]);
  }
  return users;
}

function participantsKey(users) {
  return [...users].map((u) => String(u).trim()).filter(Boolean).sort().join('|');
}

function extractSetside(body) {
  if (!body) return null;
  const patterns = [
    /setside\s*=\s*"([^"]+)"/i,
    /setsides\s*=\s*"([^"]+)"/i,
    /<setside[^>]*>\s*([^<]+)\s*</i,
    /setside[^:]*:\s*([^\n<]+)/i
  ];
  for (const re of patterns) {
    const m = re.exec(body);
    if (m && m[1] && m[1].trim()) return m[1].trim();
  }
  // x-mitel-info often embeds "120 - Name" as the setside label.
  const info = /<x-mitel-info[^>]*>([\s\S]*?)<\/x-mitel-info>/i.exec(body);
  if (info && info[1]) {
    const label = /(\d+)\s*-\s*[^\n<]+/.exec(info[1]);
    if (label) return label[0].trim();
  }
  return null;
}

function extractSipSessionId(body) {
  const ss = /<sipSessionID>([^<]+)</i.exec(body || '');
  if (ss && ss[1] && ss[1].trim()) return ss[1].split(';')[0].trim();
  return null;
}

function extractSessionId(body) {
  const sm = /<session[^>]*\ssession_id="([^"]+)"/i.exec(body || '');
  if (sm && sm[1] && sm[1].trim()) return sm[1].trim();
  return null;
}

function findDuplicateSetsideCall(callKey, pKey, setside, sipSessionId) {
  if (!pKey) return null;
  const now = Date.now();
  for (const [existingKey, existingData] of activeCalls.entries()) {
    if (existingKey === callKey) continue;
    if (existingData.participantsKey !== pKey) continue;
    if (!(existingData.pendingSetup || existingData.fsLegsActive || existingData.established)) {
      continue;
    }
    if (now - existingData.startedAt > DUPLICATE_SETSIDE_WINDOW_MS) continue;

    // Different Mitel recording session for the same two parties.
    const differentSession = existingData.primaryId !== callKey;
    const differentSetside = setside && existingData.setside &&
      setside !== existingData.setside;
    // Same underlying SIP call can share sipSessionID across setsides.
    const sameSipSession = sipSessionId && existingData.sipSessionId &&
      sipSessionId === existingData.sipSessionId;

    if (differentSession && (differentSetside || sameSipSession || !setside)) {
      return {existingKey, existingData};
    }
  }
  return null;
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
  // Digest auth uses the domain extension (e.g. 77777). Caller identity for CDR
  // must stay as the real agent — FusionPBX otherwise uses the auth extension CID.
  const fromUri = `"${agentName}" <sip:${agentExt}@${FS_DOMAIN}>`;
  const opts = {
    proxy: FS_PROXY,
    localSdp,
    callingNumber: agentExt,
    callingName: agentName,
    calledNumber: FS_CALLEE,
    headers: {
      from: fromUri,
      contact: `<sip:${agentExt}@${FS_DOMAIN}>`,
      'P-Asserted-Identity': `<sip:${agentExt}@${FS_DOMAIN}>`,
      'Remote-Party-ID': `"${agentName}" <sip:${agentExt}@${FS_DOMAIN}>;party=calling`,
      'X-SRS-Domain': FS_DOMAIN,
      'X-Room-Name': roomName,
      'X-Stream-ID': streamId,
      'X-Primary-Session': primaryId,
      'X-Is-New-Call': isNewCall,
      'X-Original-Dialed': calleeExt,
      'X-Caller-Name': agentName,
      'X-Caller-Number': agentExt,
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
  const body = req.body || '';

  const sipSessionId = extractSipSessionId(body);
  const sessionId = extractSessionId(body);
  const participantUsers = extractParticipantUsers(body);
  const pKey = participantsKey(participantUsers);
  const setside = extractSetside(body);

  // Prefer Mitel <session session_id> so each setside session is distinct.
  // sipSessionID is kept for correlation / duplicate detection only.
  const callKey = sessionId || sipSessionId || req.get('Call-ID');
  opts.logger.info({callKey, sipSessionId, sessionId, pKey, setside}, 'SIPREC call key derived');

  // Agent extension from the first participant aor (e.g. sip:1010@...). Used
  // for CDR caller fields and the record-file prefix, NOT for grouping.
  const agentAor = (participantUsers.length > 0) ? participantUsers[0] : fromUser;

  // Duplicate setside: same parties, different Mitel session, within a short
  // window. Reject — do NOT answer with another session's FS RTP ports.
  const dup = findDuplicateSetsideCall(callKey, pKey, setside, sipSessionId);
  if (dup) {
    opts.logger.warn(
      {
        callKey,
        existingKey: dup.existingKey,
        pKey,
        setside,
        existingSetside: dup.existingData.setside,
        sipSessionId
      },
      'Rejecting duplicate Mitel setside SIPREC INVITE (would reuse FS RTP ports)'
    );
    return res.send(486);
  }

  let isNewCall = 'false';
  let primaryId = callKey;

  if (!activeCalls.has(callKey)) {
    activeCalls.set(callKey, {
      primaryId: primaryId,
      agentAor: agentAor,
      sipSessionId: sipSessionId,
      participantsKey: pKey,
      setside: setside,
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

    // Same Mitel session may send another SIPREC INVITE when media changes
    // (e.g. callee answers). Update existing FS legs — do not open new ones.
    // Guard against setside mismatch so a ghost session never gets finalSdp.
    if (callData.fsLegsActive || callData.established) {
      if (setside && callData.setside && setside !== callData.setside) {
        opts.logger.warn(
          {callKey, setside, existingSetside: callData.setside},
          'Rejecting setside-mismatched follow-up SIPREC INVITE'
        );
        return res.send(486);
      }
      if (!callData.finalSdp) {
        opts.logger.warn({callKey}, 'Follow-up SIPREC INVITE while FS setup in progress; rejecting');
        return res.send(480);
      }
      opts.logger.info(
        {callKey, sessionId: parsedOpts.sessionId, setside},
        'Answering follow-up SIPREC INVITE without new FS legs'
      );
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
    if (!callData.participantsKey) callData.participantsKey = pKey;
    if (!callData.setside && setside) callData.setside = setside;
    if (!callData.sipSessionId && sipSessionId) callData.sipSessionId = sipSessionId;

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
    if (participantUsers.length > 0) agentName = participantUsers[0];
    if (participantUsers.length > 1) calleeName = participantUsers[1];

    // Force sendrecv so FreeSWITCH transmits RTP back to the MBG
    const sdp1 = normalizeStreamSdp(parsedOpts.sdp1);
    const sdp2 = normalizeStreamSdp(parsedOpts.sdp2);

    if (!FS_AUTH) {
      opts.logger.warn(
        {fsDomain: FS_DOMAIN, fsUser: FS_USER},
        'recorder.fsAuthUser/fsAuthPassword not set; FS will use public context ' +
        '(requires recorder_catch_* transfer). Set domain extension auth to skip it.'
      );
    } else {
      opts.logger.info(
        {fsDomain: FS_DOMAIN, fsUser: FS_USER, fsAuthUser: FS_AUTH_USER},
        'Using FreeSWITCH digest auth for domain context'
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
    if (err && err.status) {
      opts.logger.error(
        {status: err.status, fsDomain: FS_DOMAIN, fsUser: FS_USER, fsAuthReady: Boolean(FS_AUTH)},
        'FreeSWITCH rejected outbound INVITE (check extension auth and providers ACL)'
      );
    }
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
