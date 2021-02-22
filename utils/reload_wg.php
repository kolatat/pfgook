<?php
################################################################################
# reload_wg.php                                                                #
# For each disconnected WireGuard tunnel, check for stale endpoint and reload. #
################################################################################
require_once("web/wg.inc");

function main()
{
    global $config;
    foreach ($config["wireguard"]["tunnel"] as $tunnel) {
        if (isset($tunnel["enabled"]) && $tunnel["enabled"] == "yes") {
            check_tunnel($tunnel);
        }
    }
}

function check_tunnel($tunnel)
{
    printf("Checking tunnel %s... ", $tunnel["name"]);
    if (count($tunnel["peers"]["wgpeer"]) != 1) {
        printf("incompatible\n\n");
        return;
    }
    $endpoint = $tunnel["peers"]["wgpeer"][0];
    $peer = $endpoint["peerwgaddr"];
    if ($peer == "" || !isset($peer)) {
        printf("no peer address\n\n");
        return;
    }
    printf("\nfound peer address %s.\n", $peer);
    $out = null;
    $ret = null;
    /*
      -c      count
                   Stop after sending (and receiving) count ECHO_RESPONSE packets.
                   If this option is not specified, ping will operate until inter-
                   rupted.  If this option is specified in conjunction with ping
                   sweeps, each sweep will consist of count packets.
      -o           Exit successfully after receiving one reply packet.
      -W      waittime
                   Time in milliseconds to wait for a reply for each packet sent.
                   If a reply arrives later, the packet is not printed as replied,
                   but considered as replied when calculating statistics.
    */
    exec("/sbin/ping -o -c 3 -W 200 " . escapeshellarg($peer), $out, $ret);
    if ($ret == 0) {
        printf("pinged endpoint successfully, skipping...\n\n");
        return;
    }
    printf("endpoint ping error (retcode=%d), investigating...\n", $ret);
    // https://forums.phpfreaks.com/topic/157824-gethostbyname-for-ipv6/?do=findComment&comment=832703
    $dns4 = dns_get_record($endpoint["endpoint"], DNS_A);
    if (!$dns4) $dns4 = [];
    $dns6 = dns_get_record($endpoint["endpoint"], DNS_AAAA);
    if (!$dns6) $dns6 = [];
    $dns = array_merge($dns4, $dns6);
    $IPs = [];
    foreach ($dns as $record) {
        if ($record["type"] == "A") {
            $IPs[] = $record["ip"];
        } else if ($record["type"] == "AAAA") {
            $IPs[] = $record["ipv6"];
        }
    }
    printf("configured endpoint currently resolves to: %s\n", implode(", ", $IPs));
    $out = [];
    exec("/usr/local/bin/wg show " . escapeshellarg($tunnel["name"]), $out, $ret);
    if ($ret != 0) {
        printf("wg command error(retcode=%d)!\n\n", $ret);
        return;
    }
    $cached = "";
    foreach ($out as $line) {
        $parts = explode(":", $line);
        if (trim($parts[0]) == "endpoint") {
            $cached = trim($parts[1]);
            break;
        }
    }
    if (in_array($cached, $IPs, true)) {
        printf("cached address (%s) is fresh\nthis tool probably won't fix your problem, skipping...\n\n", $cached);
        return;
    }
    printf("cached address (%s) is stale, resetting...\n", $cached);
    reload_tunnel($tunnel);
}

function reload_tunnel($tunnel)
{
    printf("wg_configure_if(\"%s\");...\n", $tunnel["name"]);
    wg_configure_if($tunnel["name"]);
    printf("done!\n\n");
}

main();
