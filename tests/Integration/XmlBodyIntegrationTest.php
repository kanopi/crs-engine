<?php

declare(strict_types=1);

namespace Kanopi\Crs\Tests\Integration;

use Kanopi\Crs\CrsConfig;
use Kanopi\Crs\CrsEngine;
use Kanopi\Crs\Parser\SecLangParser;
use Kanopi\Crs\Request\RequestData;
use Kanopi\Crs\Runtime\CompiledRule;
use Kanopi\Crs\Runtime\RuleSet;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end: a SQLi payload smuggled inside an XML body matches a CRS-shaped
 * rule whose targets include the XML: collection.
 */
final class XmlBodyIntegrationTest extends TestCase
{
    public function testSqliInXmlBodyTriggersRule(): void
    {
        $conf = <<<'CONF'
SecRule ARGS|XML:/* "@rx (?i:union\s+.*\s+select|select\s+.*\s+from)" \
    "id:9991,phase:2,block,t:none,t:lowercase,\
    msg:'SQLi via XML body',tag:'attack-sqli',tag:'paranoia-level/1',severity:'CRITICAL',\
    setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
CONF;
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseString($conf);
        $compiled = [CompiledRule::fromArray($parsed[0]->toArray())];

        $crsEngine = new CrsEngine(new CrsConfig(), new RuleSet($compiled, 'test'));

        $crsVerdict = $crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/api/order',
            rawUri: '/api/order',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['Content-Type' => 'application/xml'],
            body: '<order><note>UNION SELECT password FROM users</note></order>',
        ));

        $this->assertTrue($crsVerdict->isBlocked(), 'SQLi inside XML element text should be caught');
    }

    public function testBenignXmlPasses(): void
    {
        $conf = <<<'CONF'
SecRule XML:/* "@rx (?i:union\s+.*\s+select)" "id:9992,phase:2,block,t:lowercase,severity:'CRITICAL',setvar:'tx.sql_injection_score=+5',setvar:'tx.inbound_anomaly_score_pl1=+5'"
CONF;
        $secLangParser = new SecLangParser();
        $parsed = $secLangParser->parseString($conf);
        $compiled = [CompiledRule::fromArray($parsed[0]->toArray())];
        $crsEngine = new CrsEngine(new CrsConfig(), new RuleSet($compiled, 'test'));

        $crsVerdict = $crsEngine->evaluate(new RequestData(
            method: 'POST',
            uri: '/api/order',
            rawUri: '/api/order',
            queryString: '',
            protocol: 'HTTP/1.1',
            remoteAddr: '127.0.0.1',
            headers: ['Content-Type' => 'application/xml'],
            body: '<order><item>shoes</item></order>',
        ));
        $this->assertFalse($crsVerdict->isBlocked());
    }
}
