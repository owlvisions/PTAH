/**
 * Network capture adapter over tshark: IP conversations and, where present,
 * HTTP requests and DNS queries. Reported under `resources` (the exchanges
 * contained in the capture). The target is never replayed; tshark reads the
 * file with "-r" only.
 */
import { ToolProvider } from "./tool-provider.mjs";

const FIELDS = [
  "frame.number",
  "ip.src",
  "ip.dst",
  "_ws.col.Protocol",
  "tcp.dstport",
  "udp.dstport",
  "http.host",
  "http.request.method",
  "http.request.uri",
  "dns.qry.name",
  "tls.handshake.extensions_server_name",
];

/** tshark -T fields rows (tab-separated), one per packet. */
export function parseTsharkFields(text) {
  const packets = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const [
      number,
      src,
      dst,
      protocol,
      tcpPort,
      udpPort,
      httpHost,
      method,
      uri,
      dnsName,
      sni,
    ] = line.split("\t");
    packets.push({
      number: Number(number),
      src: src || null,
      dst: dst || null,
      protocol: protocol || null,
      port: Number(tcpPort || udpPort) || null,
      http: method
        ? { method, host: httpHost || null, uri: uri || null }
        : null,
      dns: dnsName || null,
      sni: sni || null,
    });
  }
  return packets;
}

function summarize(packets) {
  const endpoints = new Set();
  const http = [];
  const dns = new Set();
  const sni = new Set();
  const protocols = {};
  for (const packet of packets) {
    if (packet.dst)
      endpoints.add(packet.port ? `${packet.dst}:${packet.port}` : packet.dst);
    if (packet.protocol)
      protocols[packet.protocol] = (protocols[packet.protocol] ?? 0) + 1;
    if (packet.http)
      http.push({
        host: packet.http.host,
        method: packet.http.method,
        uri: packet.http.uri,
      });
    if (packet.dns) dns.add(packet.dns);
    if (packet.sni) sni.add(packet.sni);
  }
  return {
    packetCount: packets.length,
    protocols,
    endpoints: [...endpoints],
    httpRequests: http,
    dnsQueries: [...dns],
    tlsServerNames: [...sni],
  };
}

export class TsharkProvider extends ToolProvider {
  id = "tshark";
  name = "TShark (Wireshark)";
  license = "GPL-2.0-or-later";
  executables = ["tshark"];
  versionArgs = ["--version"];
  capabilities() {
    return {
      formats: ["pcap", "pcapng"],
      tasks: { resources: { priority: 7 } },
    };
  }
  async resources(target, context) {
    const args = ["-r", "{target}", "-T", "fields", "-E", "separator=/t"];
    for (const field of FIELDS) args.push("-e", field);
    const run = await this.execute(target, args, {
      ...context,
      timeoutMs: context.timeoutMs ?? 60_000,
    });
    const summary = summarize(parseTsharkFields(run.stdout));
    return [
      this.evidence("resources", target, run, {
        summary: `${summary.packetCount} packets; ${summary.endpoints.length} endpoints; ${summary.httpRequests.length} HTTP requests; ${summary.dnsQueries.length} DNS queries`,
        data: summary,
        limitations: [
          "Encrypted payloads (TLS) are not decrypted; only metadata and cleartext fields are reported.",
        ],
      }),
    ];
  }
}

export const networkProviders = () => [new TsharkProvider()];
