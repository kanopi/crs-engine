<?php

declare(strict_types=1);

namespace Kanopi\Crs\Runtime;

use Kanopi\Crs\CrsConfig;

/**
 * Default values for CRS's `tx.*` configuration variables — the things
 * `crs-setup.conf` normally sets before any rule file is loaded.
 *
 * Without these, rules like 911100 (`!@within %{tx.allowed_methods}`) and
 * 920 protocol-enforcement series would deny every request because the
 * operator argument expands to an empty string.
 *
 * Values are pulled from upstream CRS 4.0 crs-setup.conf.example.
 */
final class CrsTxDefaults
{
    /**
     * @return array<string, string>
     */
    public static function forConfig(CrsConfig $crsConfig): array
    {
        return [
            // Version sentinel — 901001 denies if this is missing.
            'tx.crs_setup_version' => '400',

            // Paranoia.
            'tx.paranoia_level'           => (string) $crsConfig->paranoia,
            'tx.executing_paranoia_level' => (string) $crsConfig->paranoia,

            // Anomaly score constants (also inlined at parse time, but
            // some rules dereference them at runtime via %{tx.*}).
            'tx.critical_anomaly_score' => '5',
            'tx.error_anomaly_score'    => '4',
            'tx.warning_anomaly_score'  => '3',
            'tx.notice_anomaly_score'   => '2',

            // Thresholds.
            'tx.inbound_anomaly_score_threshold'  => (string) ($crsConfig->anomalyThresholds['critical'] ?? 5),
            'tx.outbound_anomaly_score_threshold' => (string) ($crsConfig->anomalyThresholds['error'] ?? 4),

            // Protocol enforcement defaults.
            'tx.allowed_methods'                        => 'GET HEAD POST OPTIONS',
            'tx.allowed_http_versions'                  => 'HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0',
            'tx.allowed_request_content_type'           => '|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/x-amf| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/octet-stream| |application/csp-report| |application/xss-auditor-report| |text/plain|',
            'tx.allowed_request_content_type_charset'   => 'utf-8|iso-8859-1|iso-8859-15|windows-1252',
            'tx.restricted_extensions'                  => '.asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/',
            'tx.restricted_headers_basic'               => '/proxy/ /lock-token/ /content-range/ /if/ /x-http-method-override/ /x-http-method/ /x-method-override/',
            'tx.restricted_headers_extended'            => '/accept-charset/',

            // Size caps.
            'tx.max_num_args'        => '255',
            'tx.arg_name_length'    => '100',
            'tx.arg_length'         => '400',
            'tx.total_arg_length'   => '64000',
            'tx.max_file_size'      => '1048576',
            'tx.combined_file_sizes' => '1048576',

            // Feature toggles — default off (most CRS deployments enable
            // them explicitly when reputation data is available).
            'tx.crs_validate_utf8_encoding' => '1',
            'tx.enforce_bodyproc_urlencoded' => '0',
            'tx.block_search_ip'    => '0',
            'tx.block_suspicious_ip' => '0',
            'tx.block_harvester_ip' => '0',
            'tx.block_spammer_ip'   => '0',
            'tx.do_reput_block'     => '0',
            'tx.reput_block_duration' => '300',
            'tx.sampling_percentage' => '100',
        ];
    }
}
