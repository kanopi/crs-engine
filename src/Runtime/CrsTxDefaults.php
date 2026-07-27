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

            // Paranoia. CRS 4 reads blocking_/detection_ and keeps the older
            // spellings for compatibility. The PL gate rules (911011 and the
            // 9xx011-9xx018 series) test detection_paranoia_level and skip a
            // whole file's block when the level is below theirs, so leaving it
            // unset silently disables the gating.
            'tx.paranoia_level'           => (string) $crsConfig->paranoia,
            'tx.executing_paranoia_level' => (string) $crsConfig->paranoia,
            'tx.blocking_paranoia_level'  => (string) $crsConfig->paranoia,
            'tx.detection_paranoia_level' => (string) $crsConfig->paranoia,

            // Anomaly accumulators, normally zero-initialised by
            // REQUEST-901-INITIALIZATION which we deliberately do not parse.
            'tx.anomaly_score'                    => '0',
            'tx.blocking_anomaly_score'           => '0',
            'tx.detection_anomaly_score'          => '0',
            'tx.inbound_anomaly_score'            => '0',
            'tx.outbound_anomaly_score'           => '0',
            'tx.blocking_inbound_anomaly_score'   => '0',
            'tx.detection_inbound_anomaly_score'  => '0',
            'tx.blocking_outbound_anomaly_score'  => '0',
            'tx.detection_outbound_anomaly_score' => '0',

            // Log verbosity, read by the 980 correlation rules.
            'tx.reporting_level' => '4',

            // Early blocking is opt-in upstream (crs-setup rule 900120).
            'tx.early_blocking' => '0',

            // Anomaly score constants (also inlined at parse time, but
            // some rules dereference them at runtime via %{tx.*}).
            'tx.critical_anomaly_score' => (string) $crsConfig->severityScore('critical'),
            'tx.error_anomaly_score'    => (string) $crsConfig->severityScore('error'),
            'tx.warning_anomaly_score'  => (string) $crsConfig->severityScore('warning'),
            'tx.notice_anomaly_score'   => (string) $crsConfig->severityScore('notice'),

            // Thresholds.
            'tx.inbound_anomaly_score_threshold'  => (string) $crsConfig->inboundThreshold(),
            'tx.outbound_anomaly_score_threshold' => (string) $crsConfig->outboundThreshold(),

            // Protocol enforcement defaults.
            'tx.allowed_methods'                        => 'GET HEAD POST OPTIONS',
            'tx.allowed_http_versions'                  => 'HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0',
            // Both of these are matched with @within, which is a substring test.
            // CRS makes that behave like an exact-element test by wrapping every
            // list entry in pipes and building the needle the same way — 920420
            // sets tx.content_type to '|%{tx.0}|' and 920480 sets
            // tx.content_type_charset to '|%{tx.1}|'. The wrapping is what stops
            // a partial like `application/js` matching, so both sides have to
            // carry it: a bare pipe-separated list leaves the first and last
            // entries without delimiters, and `|utf-8|` is then not a substring
            // of `utf-8|iso-8859-1|...`, which blocked charset=utf-8 outright.
            'tx.allowed_request_content_type'           => '|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/x-amf| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |application/octet-stream| |application/csp-report| |application/xss-auditor-report| |text/plain|',
            'tx.allowed_request_content_type_charset'   => '|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|',
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

            // UTF-8 validation is on by default, matching crs-setup.
            'tx.crs_validate_utf8_encoding' => '1',

            // Feature toggles — default off (most CRS deployments enable
            // them explicitly when reputation data is available).
            'tx.enforce_bodyproc_urlencoded' => '0',
            'tx.allow_method_override_parameter' => '0',
            'tx.crs_skip_response_analysis'  => '0',
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
