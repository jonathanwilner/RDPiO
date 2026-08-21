//! RDWeb / Windows 365 feed discovery.
//!
//! Enterprise and cloud RDP hosts are usually discovered through a feed rather
//! than typed as a bare IP. The legacy RDWeb feed is an XML document served at
//! `https://<server>/RDWeb/Feed/webfeed.aspx`; Windows 365 can expose a similar
//! feed or a JSON endpoint. This module parses both into a small [`FeedEntry`]
//! list the client can present or connect to directly.

use std::collections::HashMap;

/// One host discovered in a feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    pub id: String,
    pub display_name: String,
    pub hostname: String,
    pub port: u16,
    /// Full address as it appeared in the feed (may include `host:port`).
    pub address: String,
    pub gateway: Option<String>,
    pub load_balance_info: Option<Vec<u8>>,
    pub use_redirection_gateway: bool,
    /// Raw `.rdp` file contents, if the feed provides them inline or by URL.
    pub rdp_file: Option<String>,
    /// URL of the resource's signed `.rdp` connection file (MS-TSWP
    /// `HostingTerminalServer/ResourceFile` with extension `.rdp`). Downloading
    /// this gives Microsoft's own current connection payload — never synthesize
    /// one. `None` for feeds that do not publish resource files.
    pub rdp_url: Option<String>,
    // Windows 365 / AVD specific fields.
    /// The Azure resource id of the Cloud PC or host pool (W365 feed).
    pub resource_id: String,
    /// The Microsoft tenant id the resource belongs to.
    pub tenant_id: String,
    /// Per-session identifier used for reconnect/broker pinning.
    pub session_id: String,
    /// FQDN of the Reverse Connect gateway (e.g. `rdbroker.wvd.microsoft.com`).
    pub gateway_fqdn: String,
    /// True when the feed indicates this resource must use Reverse Connect.
    pub use_reverse_connect: bool,
}

impl Default for FeedEntry {
    fn default() -> Self {
        Self {
            id: String::new(),
            display_name: String::new(),
            hostname: String::new(),
            port: 3389,
            address: String::new(),
            gateway: None,
            load_balance_info: None,
            use_redirection_gateway: false,
            rdp_file: None,
            rdp_url: None,
            resource_id: String::new(),
            tenant_id: String::new(),
            session_id: String::new(),
            gateway_fqdn: String::new(),
            use_reverse_connect: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("network error fetching feed: {0}")]
    Network(#[from] ureq::Error),
    #[error("I/O error reading feed response: {0}")]
    Io(#[from] std::io::Error),
    #[error("feed parse error: {0}")]
    Parse(String),
    #[error("no hosts found in feed")]
    Empty,
}

/// Fetch a feed from `url` and parse every host entry it contains.
pub fn fetch(url: &str) -> Result<Vec<FeedEntry>, FeedError> {
    let body = ureq::get(url)
        .set("Accept", "application/xml, application/json, text/*")
        .call()?
        .into_string()?;
    parse(&body)
}

/// Parse a feed document already loaded into memory. XML (RDWeb webfeed) and a
/// simple JSON array format are both accepted.
pub fn parse(body: &str) -> Result<Vec<FeedEntry>, FeedError> {
    // Microsoft's webfeed responses carry a UTF-8 BOM before the XML
    // declaration; U+FEFF is not `char::is_whitespace`, so strip it explicitly.
    let trimmed = body.trim_start().trim_start_matches('\u{feff}');
    if trimmed.starts_with('<') {
        parse_xml(trimmed)
    } else if trimmed.starts_with('[') || trimmed.starts_with('{') {
        parse_json(trimmed)
    } else {
        Err(FeedError::Parse(
            "feed does not look like XML or JSON".into(),
        ))
    }
}

fn parse_xml(xml: &str) -> Result<Vec<FeedEntry>, FeedError> {
    // A real XML parser (roxmltree) is used: MS-TSWP 2.x feeds describe each
    // `<Resource>` with attributes (`ID`, `Alias`, `Title`, `Type`) and nest the
    // connection payload under `HostingTerminalServers/HostingTerminalServer/
    // ResourceFile`, while the legacy RDWeb format used child elements. The old
    // string-splitting parser could not represent either robustly (it also
    // matched `<ResourceCollection`/`<ResourceFile` as `<Resource`).
    let doc = roxmltree::Document::parse(xml).map_err(|e| FeedError::Parse(e.to_string()))?;

    let mut entries = Vec::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("Resource")) {
        let mut entry = FeedEntry::default();
        // MS-TSWP 2.x: identifiers ride on attributes.
        entry.id = node.attribute("ID").unwrap_or_default().to_string();
        entry.display_name = node
            .attribute("Title")
            .filter(|t| !t.is_empty())
            .or_else(|| node.attribute("Alias"))
            .unwrap_or_default()
            .to_string();
        // Legacy RDWeb: the same data as child elements.
        if entry.id.is_empty() {
            entry.id = text_of(node, "ID").unwrap_or_default();
        }
        if entry.display_name.is_empty() {
            entry.display_name = text_of(node, "Name").unwrap_or_default();
        }
        entry.address = text_of(node, "HostName")
            .or_else(|| text_of(node, "Address"))
            .unwrap_or_default();
        entry.gateway = text_of(node, "Gateway");
        entry.load_balance_info = text_of(node, "LoadBalanceInfo").map(|s| s.into_bytes());
        entry.use_redirection_gateway =
            text_of(node, "UseRedirectionServer").as_deref() == Some("true");
        entry.rdp_file = text_of(node, "RdpFile");

        // MS-TSWP: the signed `.rdp` connection resource, one per hosting
        // terminal server. Take the first `.rdp` ResourceFile (an AVD desktop
        // has exactly one; RemoteApp feeds may add other extensions later).
        entry.rdp_url = node
            .descendants()
            .filter(|n| n.has_tag_name("ResourceFile"))
            .find(|n| {
                n.attribute("FileExtension")
                    .map(|e| e.eq_ignore_ascii_case(".rdp"))
                    .unwrap_or(false)
            })
            .and_then(|n| n.attribute("URL"))
            .filter(|u| !u.is_empty())
            .map(str::to_string);

        // W365 / AVD fields may appear in XML feeds too.
        entry.resource_id = text_of(node, "ResourceId").unwrap_or_default();
        entry.tenant_id = text_of(node, "TenantId").unwrap_or_default();
        entry.session_id = text_of(node, "SessionId").unwrap_or_default();
        entry.gateway_fqdn = text_of(node, "GatewayFqdn").unwrap_or_default();
        entry.use_reverse_connect = text_of(node, "UseReverseConnect").as_deref() == Some("true");

        let (host, port) = split_host_port(&entry.address, 3389);
        entry.hostname = host;
        entry.port = port;

        // A TSWP entry is usable through its resource file even without a
        // direct hostname (AVD: everything is brokered through the ARM gateway).
        if !entry.hostname.is_empty() || !entry.gateway_fqdn.is_empty() || entry.rdp_url.is_some() {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return Err(FeedError::Empty);
    }
    Ok(entries)
}

fn parse_json(json: &str) -> Result<Vec<FeedEntry>, FeedError> {
    // We intentionally avoid pulling in a JSON dependency for one small feed.
    // The supported format is an array of objects with string fields.
    let mut entries = Vec::new();
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| FeedError::Parse(e.to_string()))?;
    let array = match value {
        serde_json::Value::Array(a) => a,
        serde_json::Value::Object(mut m) => m
            .remove("resources")
            .or_else(|| m.remove("value"))
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default(),
        _ => return Err(FeedError::Parse("expected array or object".into())),
    };
    for item in array {
        let obj = item
            .as_object()
            .ok_or_else(|| FeedError::Parse("expected object".into()))?;
        let mut entry = FeedEntry::default();
        entry.id = string_field(obj, "id");
        entry.display_name = string_field(obj, "displayName");
        entry.address = string_field(obj, "address");
        if entry.address.is_empty() {
            entry.address = string_field(obj, "hostname");
        }
        entry.gateway = obj
            .get("gateway")
            .and_then(|v| v.as_str())
            .map(String::from);
        entry.load_balance_info = obj
            .get("loadBalanceInfo")
            .and_then(|v| v.as_str())
            .map(|s| s.as_bytes().to_vec());
        entry.use_redirection_gateway = obj
            .get("useRedirectionServer")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        entry.rdp_file = obj
            .get("rdpFile")
            .and_then(|v| v.as_str())
            .map(String::from);

        // W365 / AVD specific fields.
        entry.resource_id = string_field(obj, "resourceId");
        if entry.resource_id.is_empty() {
            entry.resource_id = string_field(obj, "resource_id");
        }
        entry.tenant_id = string_field(obj, "tenantId");
        if entry.tenant_id.is_empty() {
            entry.tenant_id = string_field(obj, "tenant_id");
        }
        entry.session_id = string_field(obj, "sessionId");
        if entry.session_id.is_empty() {
            entry.session_id = string_field(obj, "session_id");
        }
        entry.gateway_fqdn = string_field(obj, "gatewayFqdn");
        if entry.gateway_fqdn.is_empty() {
            entry.gateway_fqdn = string_field(obj, "gateway_fqdn");
        }
        entry.use_reverse_connect = obj
            .get("useReverseConnect")
            .or_else(|| obj.get("use_reverse_connect"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let (host, port) = split_host_port(&entry.address, 3389);
        entry.hostname = host;
        entry.port = port;

        if !entry.hostname.is_empty() || !entry.gateway_fqdn.is_empty() {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return Err(FeedError::Empty);
    }
    Ok(entries)
}

fn string_field(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    obj.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Parse a minimal `.rdp` file into key/value pairs. Only the keys the client
/// cares about are surfaced; unknown keys are ignored.
pub fn parse_rdp_file(contents: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            // The type prefix (e.g. `s:`, `i:`) is skipped.
            let value = v.split_once(':').map(|(_, rest)| rest).unwrap_or(v);
            out.insert(k.to_lowercase(), value.trim().to_string());
        }
    }
    out
}

/// Apply `.rdp` file settings to a [`rdp_core::ClientConfig`].
pub fn apply_rdp_file(config: &mut rdp_core::ClientConfig, file: &str) {
    let settings = parse_rdp_file(file);
    if let Some(full) = settings.get("full address") {
        let (host, port) = split_host_port(full, config.port);
        config.hostname = host;
        config.port = port;
    }
    // W365/AVD ARM Reverse Connect: a signed `.rdp` with `resourceprovider:arm`,
    // a `gatewayhostname`, and a `loadbalanceinfo:mth://...` token. Set up Reverse
    // Connect; the caller fills in the OAuth access token afterward.
    let is_arm = settings
        .get("resourceprovider")
        .map(|s| s.eq_ignore_ascii_case("arm"))
        .unwrap_or(false);
    if let (true, Some(gw), Some(lbi)) = (
        is_arm,
        settings.get("gatewayhostname"),
        settings.get("loadbalanceinfo"),
    ) {
        let existing_token = config
            .reverse_connect
            .as_ref()
            .map(|r| r.access_token.clone())
            .unwrap_or_default();
        config.reverse_connect = Some(rdp_core::ReverseConnectConfig {
            gateway_fqdn: gw.clone(),
            load_balance_info: lbi.clone(),
            application_name: "Windows365NativeClient".to_string(),
            remote_application: settings
                .get("remoteapplicationprogram")
                .cloned()
                .unwrap_or_default(),
            tenant_id: settings.get("aadtenantid").cloned().unwrap_or_default(),
            access_token: existing_token,
            ..Default::default()
        });
    } else if let Some(gw_cfg) = crate::gateway::parse_rdp_settings(&settings) {
        crate::gateway::apply_to_config(config, &gw_cfg);
    } else if let Some(lb) = settings.get("loadbalanceinfo") {
        config.load_balance_info = Some(lb.as_bytes().to_vec());
    }
    if let Some(w) = settings.get("desktopwidth").and_then(|s| s.parse().ok()) {
        config.width = w;
    }
    if let Some(h) = settings.get("desktopheight").and_then(|s| s.parse().ok()) {
        config.height = h;
    }
}

fn split_host_port(addr: &str, default_port: u16) -> (String, u16) {
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        if let Ok(p) = port_str.parse() {
            return (host.to_string(), p);
        }
    }
    (addr.to_string(), default_port)
}

/// Text of the first direct child element `tag` of `node` (legacy RDWeb shape).
fn text_of(node: roxmltree::Node<'_, '_>, tag: &str) -> Option<String> {
    node.children()
        .find(|c| c.has_tag_name(tag))
        .and_then(|c| c.text())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_feed_parses_resource() {
        let xml = r#"<?xml version="1.0"?>
<RDWeb>
  <Resource>
    <ID>pc-1</ID>
    <Name>My Cloud PC</Name>
    <HostName>192.0.2.42:3390</HostName>
    <LoadBalanceInfo>Cookie: msts=token</LoadBalanceInfo>
  </Resource>
</RDWeb>"#;
        let entries = parse(xml).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "pc-1");
        assert_eq!(entries[0].display_name, "My Cloud PC");
        assert_eq!(entries[0].hostname, "192.0.2.42");
        assert_eq!(entries[0].port, 3390);
        assert_eq!(
            entries[0].load_balance_info,
            Some(b"Cookie: msts=token".to_vec())
        );
    }

    #[test]
    fn json_feed_parses_w365_resource() {
        let json = r#"{
            "resources": [
                {
                    "id": "w365-pc-1",
                    "displayName": "My Cloud PC",
                    "resourceId": "/subscriptions/.../cloudPCs/pc-1",
                    "tenantId": "a1b2c3d4-e5f6-...",
                    "sessionId": "session-123",
                    "gatewayFqdn": "rdbroker.wvd.microsoft.com",
                    "useReverseConnect": true,
                    "loadBalanceInfo": "Cookie: msts=token"
                }
            ]
        }"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "w365-pc-1");
        assert_eq!(entries[0].display_name, "My Cloud PC");
        assert_eq!(entries[0].resource_id, "/subscriptions/.../cloudPCs/pc-1");
        assert_eq!(entries[0].tenant_id, "a1b2c3d4-e5f6-...");
        assert_eq!(entries[0].session_id, "session-123");
        assert_eq!(entries[0].gateway_fqdn, "rdbroker.wvd.microsoft.com");
        assert!(entries[0].use_reverse_connect);
        assert_eq!(
            entries[0].load_balance_info,
            Some(b"Cookie: msts=token".to_vec())
        );
    }

    #[test]
    fn empty_feed_errors() {
        assert!(parse("<RDWeb></RDWeb>").is_err());
    }

    #[test]
    fn tswp_avd_feed_parses_resource_attributes_and_rdp_url() {
        // Real AVD shape (MS-TSWP 2.2.2): `Resource` describes the desktop with
        // attributes; the connection payload is the `.rdp` `ResourceFile` under
        // `HostingTerminalServer`. No direct hostname exists — the ARM gateway
        // brokers the connection, so `rdp_url` is the actionable output.
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<ResourceCollection PublishedDate="2024-01-01T00:00:00.000Z" SchemaVersion="2.0">
  <Publisher LastUpdated="2024-01-01T00:00:00.000Z" ID="6dfd7d72-b06f-4f27" Name="MS WVD" SupportsReconnect="true">
    <Resources>
      <Resource ID="6c7fa6ab-8f0d" Alias="SessionDesktop" Title="Session Desktop" LastUpdated="2024-01-01T00:00:00.000Z" Type="Desktop">
        <HostingTerminalServers>
          <HostingTerminalServer>
            <TerminalServerRef Ref="rds-1"/>
            <ResourceFile FileExtension=".rdp" URL="https://rdweb.wvd.microsoft.com/api/arm/v2/tenantinformationservices/Connections/discover/6c7fa6ab-8f0d.rdp"/>
          </HostingTerminalServer>
        </HostingTerminalServers>
      </Resource>
      <Resource ID="9c81cc2b-3e19" Alias="Calculator" Title="Calculator" Type="RemoteApp">
        <HostingTerminalServers>
          <HostingTerminalServer>
            <TerminalServerRef Ref="rds-1"/>
            <ResourceFile FileExtension=".rdp" URL="https://rdweb.wvd.microsoft.com/api/arm/v2/tenantinformationservices/Connections/discover/9c81cc2b-3e19.rdp"/>
            <ResourceFile FileExtension=".msrcincident" URL="https://example/ignore.rdp.wrong"/>
          </HostingTerminalServer>
        </HostingTerminalServers>
      </Resource>
    </Resources>
    <TerminalServers>
      <TerminalServer ID="rds-1" Name="rds-abcdef.wvd.microsoft.com"/>
    </TerminalServers>
  </Publisher>
</ResourceCollection>"#;
        let entries = parse(xml).unwrap();
        assert_eq!(entries.len(), 2);
        let desktop = &entries[0];
        assert_eq!(desktop.id, "6c7fa6ab-8f0d");
        assert_eq!(desktop.display_name, "Session Desktop");
        assert_eq!(
            desktop.rdp_url.as_deref(),
            Some("https://rdweb.wvd.microsoft.com/api/arm/v2/tenantinformationservices/Connections/discover/6c7fa6ab-8f0d.rdp")
        );
        // The RemoteApp entry is selected by its own resource file, not the
        // desktop's (and non-.rdp extensions are ignored).
        assert!(entries[1]
            .rdp_url
            .as_deref()
            .unwrap()
            .contains("9c81cc2b-3e19.rdp"));
        // No direct address in a TSWP feed; the entry is still usable.
        assert!(desktop.hostname.is_empty());
    }

    #[test]
    fn tswp_url_entities_are_decoded() {
        let xml = r#"<ResourceCollection><Publisher><Resources>
          <Resource ID="a" Alias="d" Title="D" Type="Desktop">
            <HostingTerminalServers><HostingTerminalServer>
              <ResourceFile FileExtension=".rdp" URL="https://host/path?a=1&amp;b=2"/>
            </HostingTerminalServer></HostingTerminalServers>
          </Resource>
        </Resources></Publisher></ResourceCollection>"#;
        let entries = parse(xml).unwrap();
        assert_eq!(
            entries[0].rdp_url.as_deref(),
            Some("https://host/path?a=1&b=2")
        );
    }

    #[test]
    fn rdp_file_applies_to_config() {
        let file = r#"full address:s:10.0.0.99:3389
desktopwidth:i:1920
desktopheight:i:1080"#;
        let mut config = rdp_core::ClientConfig::default();
        apply_rdp_file(&mut config, file);
        assert_eq!(config.hostname, "10.0.0.99");
        assert_eq!(config.port, 3389);
        assert_eq!(config.width, 1920);
        assert_eq!(config.height, 1080);
    }
}
