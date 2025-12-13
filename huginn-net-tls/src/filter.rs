use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Filter mode: Allow (allowlist) or Deny (denylist)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterMode {
    /// Allow only matching packets (allowlist mode)
    #[default]
    Allow,
    /// Deny matching packets (denylist mode)
    Deny,
}

/// Port filter configuration
///
/// Filters packets based on TCP source and/or destination ports.
/// Supports individual ports, ranges, and lists.
///
/// # Examples
///
/// ```rust
/// use huginn_net_tls::PortFilter;
///
/// // Single port
/// let filter = PortFilter::new().destination(443);
///
/// // Multiple ports
/// let filter = PortFilter::new().destination_list(vec![80, 443, 8080]);
///
/// // Port range
/// let filter = PortFilter::new().destination_range(8000..9000);
/// ```
#[derive(Debug, Clone, Default)]
pub struct PortFilter {
    /// Source ports to match
    pub source_ports: Vec<u16>,
    /// Destination ports to match
    pub destination_ports: Vec<u16>,
    /// Source port ranges (inclusive)
    pub source_ranges: Vec<(u16, u16)>,
    /// Destination port ranges (inclusive)
    pub destination_ranges: Vec<(u16, u16)>,
    /// Match ANY port (source OR destination)?
    pub match_any: bool,
}

impl PortFilter {
    /// Create a new empty port filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a destination port
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::PortFilter;
    ///
    /// let filter = PortFilter::new().destination(443);
    /// ```
    pub fn destination(mut self, port: u16) -> Self {
        self.destination_ports.push(port);
        self
    }

    /// Add a source port
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::PortFilter;
    ///
    /// let filter = PortFilter::new().source(12345);
    /// ```
    pub fn source(mut self, port: u16) -> Self {
        self.source_ports.push(port);
        self
    }

    /// Add a destination port range (inclusive)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::PortFilter;
    ///
    /// let filter = PortFilter::new().destination_range(8000..9000);
    /// // Matches ports 8000 through 8999
    /// ```
    pub fn destination_range(mut self, range: std::ops::Range<u16>) -> Self {
        self.destination_ranges
            .push((range.start, range.end.saturating_sub(1)));
        self
    }

    /// Add a source port range (inclusive)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::PortFilter;
    ///
    /// let filter = PortFilter::new().source_range(10000..20000);
    /// // Matches ports 10000 through 19999
    /// ```
    pub fn source_range(mut self, range: std::ops::Range<u16>) -> Self {
        self.source_ranges
            .push((range.start, range.end.saturating_sub(1)));
        self
    }

    /// Add multiple destination ports
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::PortFilter;
    ///
    /// let filter = PortFilter::new().destination_list(vec![80, 443, 8080, 8443]);
    /// ```
    pub fn destination_list(mut self, ports: Vec<u16>) -> Self {
        self.destination_ports.extend(ports);
        self
    }

    /// Add multiple source ports
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::PortFilter;
    ///
    /// let filter = PortFilter::new().source_list(vec![12345, 54321, 9999]);
    /// ```
    pub fn source_list(mut self, ports: Vec<u16>) -> Self {
        self.source_ports.extend(ports);
        self
    }

    /// Match if ANY port matches (source OR destination)
    ///
    /// By default, all specified filters must match. With `match_any()`,
    /// the packet passes if either source OR destination matches.
    pub fn any_port(mut self) -> Self {
        self.match_any = true;
        self
    }

    /// Check if packet matches port filter
    ///
    /// # Returns
    ///
    /// `true` if the packet matches the filter criteria
    pub fn matches(&self, src_port: u16, dst_port: u16) -> bool {
        if self.match_any {
            let all_ports: Vec<u16> = self
                .source_ports
                .iter()
                .chain(self.destination_ports.iter())
                .copied()
                .collect();

            let all_ranges: Vec<(u16, u16)> = self
                .source_ranges
                .iter()
                .chain(self.destination_ranges.iter())
                .copied()
                .collect();

            let port_match = all_ports.contains(&src_port)
                || all_ports.contains(&dst_port)
                || all_ranges
                    .iter()
                    .any(|(start, end)| src_port >= *start && src_port <= *end)
                || all_ranges
                    .iter()
                    .any(|(start, end)| dst_port >= *start && dst_port <= *end);

            port_match
        } else {
            let src_match = self.source_ports.contains(&src_port)
                || self
                    .source_ranges
                    .iter()
                    .any(|(start, end)| src_port >= *start && src_port <= *end);

            let dst_match = self.destination_ports.contains(&dst_port)
                || self
                    .destination_ranges
                    .iter()
                    .any(|(start, end)| dst_port >= *start && dst_port <= *end);

            let src_ok = self.source_ports.is_empty() && self.source_ranges.is_empty() || src_match;
            let dst_ok = self.destination_ports.is_empty() && self.destination_ranges.is_empty()
                || dst_match;
            src_ok && dst_ok
        }
    }
}

/// IP address filter configuration
///
/// Filters packets based on specific IPv4 or IPv6 addresses.
///
/// # Examples
///
/// ```rust
/// use huginn_net_tls::IpFilter;
///
/// let filter = IpFilter::new()
///     .allow("8.8.8.8")
///     .unwrap()
///     .allow("2001:4860:4860::8888")
///     .unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    /// IPv4 addresses to match
    pub ipv4_addresses: Vec<Ipv4Addr>,
    /// IPv6 addresses to match
    pub ipv6_addresses: Vec<Ipv6Addr>,
    /// Check source, destination, or both?
    pub check_source: bool,
    pub check_destination: bool,
}

impl IpFilter {
    /// Create a new IP filter that checks both source and destination by default
    pub fn new() -> Self {
        Self { check_source: true, check_destination: true, ..Default::default() }
    }

    /// Add an IP address (auto-detects IPv4/IPv6)
    ///
    /// # Errors
    ///
    /// Returns an error if the IP address string is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::IpFilter;
    ///
    /// let filter = IpFilter::new()
    ///     .allow("192.168.1.1").unwrap()
    ///     .allow("2001:db8::1").unwrap();
    /// ```
    pub fn allow(mut self, ip: &str) -> Result<Self, String> {
        let addr: IpAddr = ip.parse().map_err(|e| format!("Invalid IP: {e}"))?;
        match addr {
            IpAddr::V4(v4) => self.ipv4_addresses.push(v4),
            IpAddr::V6(v6) => self.ipv6_addresses.push(v6),
        }
        Ok(self)
    }

    /// Add multiple IP addresses
    ///
    /// # Errors
    ///
    /// Returns an error if any IP address string is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::IpFilter;
    ///
    /// let filter = IpFilter::new()
    ///     .allow_list(vec!["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"])
    ///     .unwrap();
    /// ```
    pub fn allow_list(mut self, ips: Vec<&str>) -> Result<Self, String> {
        for ip in ips {
            self = self.allow(ip)?;
        }
        Ok(self)
    }

    /// Only check source addresses
    ///
    /// By default, both source and destination are checked.
    pub fn source_only(mut self) -> Self {
        self.check_source = true;
        self.check_destination = false;
        self
    }

    /// Only check destination addresses
    ///
    /// By default, both source and destination are checked.
    pub fn destination_only(mut self) -> Self {
        self.check_source = false;
        self.check_destination = true;
        self
    }

    /// Check if packet matches IP filter
    ///
    /// # Returns
    ///
    /// `true` if either source or destination IP matches (if enabled)
    pub fn matches(&self, src_ip: &IpAddr, dst_ip: &IpAddr) -> bool {
        let src_match = if self.check_source {
            match src_ip {
                IpAddr::V4(v4) => self.ipv4_addresses.contains(v4),
                IpAddr::V6(v6) => self.ipv6_addresses.contains(v6),
            }
        } else {
            false
        };

        let dst_match = if self.check_destination {
            match dst_ip {
                IpAddr::V4(v4) => self.ipv4_addresses.contains(v4),
                IpAddr::V6(v6) => self.ipv6_addresses.contains(v6),
            }
        } else {
            false
        };

        src_match || dst_match
    }
}

/// Subnet filter configuration (CIDR notation)
///
/// Filters packets based on subnet membership using CIDR notation.
/// Supports both IPv4 and IPv6 subnets.
///
/// # Examples
///
/// ```rust
/// use huginn_net_tls::SubnetFilter;
///
/// // Allow only private networks
/// let filter = SubnetFilter::new()
///     .allow("192.168.0.0/16").unwrap()
///     .allow("10.0.0.0/8").unwrap();
///
/// // IPv6 subnet
/// let filter = SubnetFilter::new()
///     .allow("2001:db8::/32").unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SubnetFilter {
    /// IPv4 subnets to match
    pub ipv4_subnets: Vec<Ipv4Network>,
    /// IPv6 subnets to match
    pub ipv6_subnets: Vec<Ipv6Network>,
    /// Check source, destination, or both?
    pub check_source: bool,
    pub check_destination: bool,
}

impl SubnetFilter {
    /// Create a new subnet filter that checks both source and destination by default
    pub fn new() -> Self {
        Self { check_source: true, check_destination: true, ..Default::default() }
    }

    /// Add a subnet in CIDR notation
    ///
    /// # Errors
    ///
    /// Returns an error if the CIDR notation is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::SubnetFilter;
    ///
    /// let filter = SubnetFilter::new()
    ///     .allow("192.168.1.0/24").unwrap();
    /// ```
    pub fn allow(mut self, cidr: &str) -> Result<Self, String> {
        let network: IpNetwork = cidr.parse().map_err(|e| format!("Invalid CIDR: {e}"))?;
        match network {
            IpNetwork::V4(v4) => self.ipv4_subnets.push(v4),
            IpNetwork::V6(v6) => self.ipv6_subnets.push(v6),
        }
        Ok(self)
    }

    /// Add multiple subnets
    ///
    /// # Errors
    ///
    /// Returns an error if any CIDR notation is invalid
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::SubnetFilter;
    ///
    /// let filter = SubnetFilter::new()
    ///     .allow_list(vec!["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
    ///     .unwrap();
    /// ```
    pub fn allow_list(mut self, cidrs: Vec<&str>) -> Result<Self, String> {
        for cidr in cidrs {
            self = self.allow(cidr)?;
        }
        Ok(self)
    }

    /// Only check source addresses
    ///
    /// By default, both source and destination are checked.
    pub fn source_only(mut self) -> Self {
        self.check_source = true;
        self.check_destination = false;
        self
    }

    /// Only check destination addresses
    ///
    /// By default, both source and destination are checked.
    pub fn destination_only(mut self) -> Self {
        self.check_source = false;
        self.check_destination = true;
        self
    }

    /// Check if packet matches subnet filter
    ///
    /// # Returns
    ///
    /// `true` if either source or destination IP is in any of the subnets (if enabled)
    pub fn matches(&self, src_ip: &IpAddr, dst_ip: &IpAddr) -> bool {
        let src_match = if self.check_source {
            match src_ip {
                IpAddr::V4(v4) => self.ipv4_subnets.iter().any(|net| net.contains(*v4)),
                IpAddr::V6(v6) => self.ipv6_subnets.iter().any(|net| net.contains(*v6)),
            }
        } else {
            false
        };

        let dst_match = if self.check_destination {
            match dst_ip {
                IpAddr::V4(v4) => self.ipv4_subnets.iter().any(|net| net.contains(*v4)),
                IpAddr::V6(v6) => self.ipv6_subnets.iter().any(|net| net.contains(*v6)),
            }
        } else {
            false
        };

        src_match || dst_match
    }
}

/// Combined filter configuration
///
/// Combines port, IP, and subnet filters with a filter mode (Allow/Deny).
/// All enabled filters must pass for a packet to be processed.
///
/// # Examples
///
/// ```rust
/// use huginn_net_tls::{FilterConfig, FilterMode, PortFilter, SubnetFilter};
///
/// let filter = FilterConfig::new()
///     .mode(FilterMode::Allow)
///     .with_port_filter(PortFilter::new().destination(443))
///     .with_subnet_filter(
///         SubnetFilter::new()
///             .allow("192.168.0.0/16")
///             .unwrap()
///     );
/// ```
#[derive(Debug, Clone, Default)]
pub struct FilterConfig {
    pub port_filter: Option<PortFilter>,
    pub ip_filter: Option<IpFilter>,
    pub subnet_filter: Option<SubnetFilter>,
    pub mode: FilterMode,
}

impl FilterConfig {
    /// Create a new empty filter configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set filter mode (Allow/Deny)
    ///
    /// # Examples
    ///
    /// ```
    /// use huginn_net_tls::{FilterConfig, FilterMode};
    ///
    /// // Allowlist mode (default) - only matching packets pass
    /// let filter = FilterConfig::new().mode(FilterMode::Allow);
    ///
    /// // Denylist mode - matching packets are blocked
    /// let filter = FilterConfig::new().mode(FilterMode::Deny);
    /// ```
    pub fn mode(mut self, mode: FilterMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add port filter
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::{FilterConfig, PortFilter};
    ///
    /// let filter = FilterConfig::new()
    ///     .with_port_filter(PortFilter::new().destination(443));
    /// ```
    pub fn with_port_filter(mut self, filter: PortFilter) -> Self {
        self.port_filter = Some(filter);
        self
    }

    /// Add IP filter
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::{FilterConfig, IpFilter};
    ///
    /// let filter = FilterConfig::new()
    ///     .with_ip_filter(
    ///         IpFilter::new()
    ///             .allow("8.8.8.8")
    ///             .unwrap()
    ///     );
    /// ```
    pub fn with_ip_filter(mut self, filter: IpFilter) -> Self {
        self.ip_filter = Some(filter);
        self
    }

    /// Add subnet filter
    ///
    /// # Examples
    ///
    /// ```rust
    /// use huginn_net_tls::{FilterConfig, SubnetFilter};
    ///
    /// let filter = FilterConfig::new()
    ///     .with_subnet_filter(
    ///         SubnetFilter::new()
    ///             .allow("192.168.0.0/16")
    ///             .unwrap()
    ///     );
    /// ```
    pub fn with_subnet_filter(mut self, filter: SubnetFilter) -> Self {
        self.subnet_filter = Some(filter);
        self
    }

    /// Check if packet should be processed based on filters (userspace filtering)
    ///
    /// This method performs filtering in userspace after packets reach the application.
    /// It extracts IP addresses and ports from packet headers and applies the configured
    /// filters (port, IP, subnet) according to the filter mode (Allow/Deny).
    ///
    /// # Returns
    ///
    /// - `true`: Packet passes all filters (should be processed)
    /// - `false`: Packet blocked by filters (should be dropped)
    ///
    /// # Logic
    ///
    /// - If no filters are configured, all packets pass
    /// - In Allow mode: packet must match ALL configured filters
    /// - In Deny mode: packet must NOT match ALL configured filters
    pub fn should_process(
        &self,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        if self.port_filter.is_none() && self.ip_filter.is_none() && self.subnet_filter.is_none() {
            return true;
        }

        match self.mode {
            FilterMode::Allow => {
                if let Some(ref filter) = self.port_filter {
                    if !filter.matches(src_port, dst_port) {
                        return false;
                    }
                }

                if let Some(ref filter) = self.ip_filter {
                    if !filter.matches(src_ip, dst_ip) {
                        return false;
                    }
                }

                if let Some(ref filter) = self.subnet_filter {
                    if !filter.matches(src_ip, dst_ip) {
                        return false;
                    }
                }

                true
            }
            FilterMode::Deny => {
                let mut all_match = true;

                if let Some(ref filter) = self.port_filter {
                    all_match = all_match && filter.matches(src_port, dst_port);
                }

                if let Some(ref filter) = self.ip_filter {
                    all_match = all_match && filter.matches(src_ip, dst_ip);
                }

                if let Some(ref filter) = self.subnet_filter {
                    all_match = all_match && filter.matches(src_ip, dst_ip);
                }

                !all_match
            }
        }
    }
}
