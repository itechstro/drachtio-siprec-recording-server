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
const FS_URI       = `sip:${FS_USER}@${FS_ADDRESS}:${FS_PORT}`;

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

  // PER-CALL KEY: the From user is always the recording client ("MitelSipRec")
  // and the agent extension is shared across every call that agent makes, so
  // neither can tell one CALL from the next. Mitel's rs-metadata carries a
  // <session session_id="..."> that is identical across the two SIPREC INVITEs
  // belonging to one recorded call and unique per call. Keying on it gives
  // exactly one logical recording per call: each call gets its own primaryId
  // (hence its own X-Primary-Session, conference record file, and single
  // process_cdr=true leg), and rapid OR overlapping same-agent calls no longer
  // collapse onto one shared recording.
  let callKey = req.get('Call-ID');
  try {
    const sm = /session_id="([^"]+)"/i.exec(req.body);
    if (sm && sm[1] && sm[1].trim()) callKey = sm[1].trim();
  } catch (e) {
    opts.logger.error('Failed to derive session_id from metadata; using Call-ID');
  }

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

  if (!activeCalls.has(callKey)) {
    activeCalls.set(callKey, { primaryId: primaryId, streams: new Set(), timeout: null });
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
    activeCalls.get(callKey).streams.add(parsedOpts.sessionId);

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

    // FIREWALL KEEP-ALIVE: Force sendrecv so FreeSWITCH transmits RTP back to the MBG
    const sdp1 = parsedOpts.sdp1.replace(/a=sendonly/g, 'a=sendrecv');
    const sdp2 = parsedOpts.sdp2.replace(/a=sendonly/g, 'a=sendrecv');

    const [uac1, uac2] = await Promise.all([
      srf.createUAC(fsUri, {
        localSdp: sdp1,
        callingNumber: agentExt,
        callingName: agentName,
        calledNumber: 'recorder',
        headers: {
          'X-Room-Name': roomName,
          'X-Stream-ID': '1',
          'X-Primary-Session': primaryId,
          'X-Is-New-Call': isNewCall,
          'X-Original-Dialed': calleeExt,
          'X-Caller-Name': agentName,
          'X-Callee-Name': calleeName
        }
      }),
      srf.createUAC(fsUri, {
        localSdp: sdp2,
        callingNumber: agentExt,
        callingName: agentName,
        calledNumber: 'recorder',
        headers: {
          'X-Room-Name': roomName,
          'X-Stream-ID': '2',
          'X-Primary-Session': primaryId,
          'X-Is-New-Call': isNewCall,
          'X-Original-Dialed': calleeExt,
          'X-Caller-Name': agentName,
          'X-Callee-Name': calleeName
        }
      })
    ]);

    const fsPublicIp = FS_PUBLIC_IP;
    const mitelSdp = transform.parse(parsedOpts.sdp1);
    const fsSdp1 = transform.parse(uac1.remote.sdp);
    const fsSdp2 = transform.parse(uac2.remote.sdp);

    // IP FIX: Provide FreeSWITCH's public IP so Mitel knows exactly where to send the RTP
    mitelSdp.connection = { version: 4, ip: fsPublicIp };

    // Hack FreeSWITCH's answer back to recvonly to keep Mitel's SRC engine happy
    fsSdp1.media[0].direction = 'recvonly';
    if (fsSdp1.media[0].connection) fsSdp1.media[0].connection.ip = fsPublicIp;
    else fsSdp1.media[0].connection = { version: 4, ip: fsPublicIp };

    fsSdp2.media[0].direction = 'recvonly';
    if (fsSdp2.media[0].connection) fsSdp2.media[0].connection.ip = fsPublicIp;
    else fsSdp2.media[0].connection = { version: 4, ip: fsPublicIp };

    mitelSdp.media = [ fsSdp1.media[0], fsSdp2.media[0] ];
    const finalSdp = transform.write(mitelSdp);

    const uas = await srf.createUAS(req, res, {
      localSdp: finalSdp
    });

    // TIMEOUT FIX: Automatically accept SIP Session Refresh timers from Mitel
    uas.on('modify', (req, res) => {
      res.send(200, { body: finalSdp });
    });

    const cleanup = () => {
      if (activeCalls.has(callKey)) {
        const callData = activeCalls.get(callKey);
        callData.streams.delete(parsedOpts.sessionId);
        if (callData.streams.size === 0) {
          callData.timeout = setTimeout(() => {
            activeCalls.delete(callKey);
          }, 10000);
        }
      }
    };

    uas.on('destroy', () => { cleanup(); uac1.destroy(); uac2.destroy(); });
    uac1.on('destroy', () => { cleanup(); uas.destroy(); });
    uac2.on('destroy', () => { cleanup(); uas.destroy(); });

  } catch (err) {
    opts.logger.error(err, 'Error pushing SIPREC streams to FreeSWITCH');
    // Roll back the map entry: a failed setup must not leave the call key
    // wedged in the Map, or the retried/!next INVITE reads isNewCall=false.
    if (activeCalls.has(callKey)) {
      const callData = activeCalls.get(callKey);
      if (parsedOpts && parsedOpts.sessionId) callData.streams.delete(parsedOpts.sessionId);
      if (callData.streams.size === 0) {
        if (callData.timeout) clearTimeout(callData.timeout);
        activeCalls.delete(callKey);
      }
    }
    if (!res.headersSent) res.send(480);
  }
}
