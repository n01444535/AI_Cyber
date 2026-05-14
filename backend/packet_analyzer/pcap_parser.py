from pathlib import Path

from backend.models import ParsedPacketRecord


def parse_pcap_file(pcap_file_path: str) -> list[ParsedPacketRecord]:
    file_path = Path(pcap_file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_file_path}")

    try:
        from scapy.all import rdpcap

        raw_packets = rdpcap(pcap_file_path)
        return _extract_records_from_scapy_packets(raw_packets)
    except ImportError:
        pass

    try:
        import pyshark  # noqa: F401

        return _extract_records_from_pyshark(pcap_file_path)
    except ImportError:
        raise RuntimeError(
            "Neither scapy nor pyshark is installed. Install one to parse PCAP files."
        )


def _extract_records_from_scapy_packets(raw_packets) -> list[ParsedPacketRecord]:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.dns import DNS, DNSQR

    parsed_records: list[ParsedPacketRecord] = []

    for frame_index, raw_packet in enumerate(raw_packets):
        record = _build_record_from_scapy_packet(
            raw_packet, frame_index, IP, TCP, UDP, ICMP, Ether, ARP, DNS, DNSQR
        )
        if record:
            parsed_records.append(record)

    return parsed_records


def _build_record_from_scapy_packet(
    raw_packet, frame_index, IP, TCP, UDP, ICMP, Ether, ARP, DNS, DNSQR
) -> ParsedPacketRecord | None:
    packet_timestamp = float(raw_packet.time)
    packet_length = len(raw_packet)

    source_ip = ""
    destination_ip = ""
    source_port = 0
    destination_port = 0
    protocol = "OTHER"
    hop_limit = 0
    tcp_flags_syn = tcp_flags_ack = tcp_flags_rst = 0
    tcp_flags_fin = tcp_flags_psh = tcp_flags_urg = 0
    http_method = http_uri = http_status_code = http_user_agent = ""
    dns_query_name = dns_response_code = ""
    is_dns_ptr_query = 0
    arp_opcode = 0
    source_mac = arp_target_ip = ""
    smb_command = tls_sni = ""

    if raw_packet.haslayer(IP):
        ip_layer = raw_packet[IP]
        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        hop_limit = ip_layer.ttl

        if raw_packet.haslayer(TCP):
            tcp_layer = raw_packet[TCP]
            source_port = tcp_layer.sport
            destination_port = tcp_layer.dport
            protocol = "TCP"
            tcp_flags = tcp_layer.flags
            tcp_flags_syn = int(bool(tcp_flags & 0x02))
            tcp_flags_ack = int(bool(tcp_flags & 0x10))
            tcp_flags_rst = int(bool(tcp_flags & 0x04))
            tcp_flags_fin = int(bool(tcp_flags & 0x01))
            tcp_flags_psh = int(bool(tcp_flags & 0x08))
            tcp_flags_urg = int(bool(tcp_flags & 0x20))

            tls_sni = _extract_tls_sni_from_scapy(raw_packet)
            smb_command = _extract_smb_command_from_scapy(raw_packet)

        elif raw_packet.haslayer(UDP):
            udp_layer = raw_packet[UDP]
            source_port = udp_layer.sport
            destination_port = udp_layer.dport
            protocol = "UDP"

        elif raw_packet.haslayer(ICMP):
            protocol = "ICMP"

        if raw_packet.haslayer(DNS):
            dns_layer = raw_packet[DNS]
            dns_response_code = str(dns_layer.rcode)
            if raw_packet.haslayer(DNSQR):
                dns_qr_layer = raw_packet[DNSQR]
                dns_query_name = dns_qr_layer.qname.decode("utf-8", errors="replace").rstrip(".")
                is_dns_ptr_query = int(dns_qr_layer.qtype == 12)

    elif raw_packet.haslayer(ARP):
        arp_layer = raw_packet[ARP]
        protocol = "ARP"
        source_ip = arp_layer.psrc
        destination_ip = arp_layer.pdst
        arp_opcode = arp_layer.op
        arp_target_ip = arp_layer.pdst
        if raw_packet.haslayer(Ether):
            source_mac = raw_packet[Ether].src

    if not source_ip and not destination_ip:
        return None

    return ParsedPacketRecord(
        timestamp=packet_timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_length=packet_length,
        tcp_flags_syn=tcp_flags_syn,
        tcp_flags_ack=tcp_flags_ack,
        tcp_flags_rst=tcp_flags_rst,
        tcp_flags_fin=tcp_flags_fin,
        tcp_flags_psh=tcp_flags_psh,
        tcp_flags_urg=tcp_flags_urg,
        hop_limit=hop_limit,
        frame_number=frame_index,
        http_method=http_method,
        http_uri=http_uri,
        http_status_code=http_status_code,
        http_user_agent=http_user_agent,
        dns_query_name=dns_query_name,
        dns_response_code=dns_response_code,
        is_dns_ptr_query=is_dns_ptr_query,
        arp_opcode=arp_opcode,
        source_mac=source_mac,
        arp_target_ip=arp_target_ip,
        smb_command=smb_command,
        tls_sni=tls_sni,
    )


def _extract_tls_sni_from_scapy(raw_packet) -> str:
    try:
        raw_bytes = bytes(raw_packet)
        # TLS ClientHello starts with 0x16 0x03 (TLS record + version)
        tls_record_type = 0x16
        tls_handshake_type_client_hello = 0x01

        tls_start = raw_bytes.find(bytes([tls_record_type, 0x03]))
        if tls_start == -1:
            return ""
        if len(raw_bytes) < tls_start + 6:
            return ""
        if raw_bytes[tls_start + 5] != tls_handshake_type_client_hello:
            return ""

        sni_marker = b"\x00\x00"
        sni_pos = raw_bytes.find(sni_marker, tls_start + 40)
        if sni_pos == -1 or sni_pos + 9 >= len(raw_bytes):
            return ""

        sni_length = int.from_bytes(raw_bytes[sni_pos + 7 : sni_pos + 9], "big")
        sni_end = sni_pos + 9 + sni_length
        if sni_end > len(raw_bytes):
            return ""
        return raw_bytes[sni_pos + 9 : sni_end].decode("ascii", errors="ignore")
    except Exception:
        return ""


def _extract_smb_command_from_scapy(raw_packet) -> str:
    try:
        raw_bytes = bytes(raw_packet)
        smb1_magic = b"\xffSMB"
        smb2_magic = b"\xfeSMB"

        smb1_pos = raw_bytes.find(smb1_magic)
        if smb1_pos != -1 and smb1_pos + 5 < len(raw_bytes):
            smb1_command_byte = raw_bytes[smb1_pos + 4]
            return f"SMBv1-cmd-{smb1_command_byte:#04x}"

        smb2_pos = raw_bytes.find(smb2_magic)
        if smb2_pos != -1 and smb2_pos + 14 < len(raw_bytes):
            smb2_command_bytes = raw_bytes[smb2_pos + 12 : smb2_pos + 14]
            smb2_command_id = int.from_bytes(smb2_command_bytes, "little")
            return f"SMBv2-cmd-{smb2_command_id}"

        return ""
    except Exception:
        return ""


def _extract_records_from_pyshark(pcap_file_path: str) -> list[ParsedPacketRecord]:
    import pyshark

    parsed_records: list[ParsedPacketRecord] = []
    capture = pyshark.FileCapture(pcap_file_path, keep_packets=False)

    for frame_index, raw_packet in enumerate(capture):
        record = _build_record_from_pyshark_packet(raw_packet, frame_index)
        if record:
            parsed_records.append(record)

    capture.close()
    return parsed_records


def _build_record_from_pyshark_packet(raw_packet, frame_index: int) -> ParsedPacketRecord | None:
    try:
        source_ip = ""
        destination_ip = ""
        source_port = 0
        destination_port = 0
        protocol = "OTHER"
        hop_limit = 0
        packet_length = int(getattr(raw_packet, "length", 0))
        packet_timestamp = float(raw_packet.sniff_timestamp)

        tcp_flags_syn = tcp_flags_ack = tcp_flags_rst = 0
        tcp_flags_fin = tcp_flags_psh = tcp_flags_urg = 0
        dns_query_name = dns_response_code = ""
        is_dns_ptr_query = 0
        arp_opcode = 0
        source_mac = arp_target_ip = ""
        smb_command = tls_sni = ""

        if hasattr(raw_packet, "ip"):
            source_ip = raw_packet.ip.src
            destination_ip = raw_packet.ip.dst
            hop_limit = int(raw_packet.ip.ttl)

        if hasattr(raw_packet, "tcp"):
            source_port = int(raw_packet.tcp.srcport)
            destination_port = int(raw_packet.tcp.dstport)
            protocol = "TCP"
            tcp_flags_syn = int(raw_packet.tcp.flags_syn)
            tcp_flags_ack = int(raw_packet.tcp.flags_ack)
            tcp_flags_rst = int(raw_packet.tcp.flags_reset)
            tcp_flags_fin = int(raw_packet.tcp.flags_fin)
            tcp_flags_psh = int(raw_packet.tcp.flags_push)
            tcp_flags_urg = int(raw_packet.tcp.flags_urg)

        elif hasattr(raw_packet, "udp"):
            source_port = int(raw_packet.udp.srcport)
            destination_port = int(raw_packet.udp.dstport)
            protocol = "UDP"

        elif hasattr(raw_packet, "icmp"):
            protocol = "ICMP"

        if hasattr(raw_packet, "dns"):
            dns_layer = raw_packet.dns
            dns_response_code = getattr(dns_layer, "flags_rcode", "")
            dns_query_name = getattr(dns_layer, "qry_name", "")
            is_dns_ptr_query = int(getattr(dns_layer, "qry_type", "") == "12")

        if hasattr(raw_packet, "arp"):
            protocol = "ARP"
            arp_opcode = int(getattr(raw_packet.arp, "opcode", 0))
            source_ip = getattr(raw_packet.arp, "src_proto_ipv4", "")
            destination_ip = getattr(raw_packet.arp, "dst_proto_ipv4", "")
            source_mac = getattr(raw_packet.arp, "src_hw_mac", "")
            arp_target_ip = destination_ip

        if not source_ip:
            return None

        return ParsedPacketRecord(
            timestamp=packet_timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            packet_length=packet_length,
            tcp_flags_syn=tcp_flags_syn,
            tcp_flags_ack=tcp_flags_ack,
            tcp_flags_rst=tcp_flags_rst,
            tcp_flags_fin=tcp_flags_fin,
            tcp_flags_psh=tcp_flags_psh,
            tcp_flags_urg=tcp_flags_urg,
            hop_limit=hop_limit,
            frame_number=frame_index,
            dns_query_name=dns_query_name,
            dns_response_code=dns_response_code,
            is_dns_ptr_query=is_dns_ptr_query,
            arp_opcode=arp_opcode,
            source_mac=source_mac,
            arp_target_ip=arp_target_ip,
            smb_command=smb_command,
            tls_sni=tls_sni,
        )
    except Exception:
        return None
