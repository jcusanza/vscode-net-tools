import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { Address6 } from "ip-address";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { ICMPPacket } from "./icmpPacket";
import { TCPPacket } from "./tcpPacket";
import { UDPPacket } from "./udpPacket";
import { ICMPv6Packet } from "./icmpv6Packet";

export class IPv6Packet extends GenericPacket {
	public static readonly Name = "IPv6";

	private static readonly _VersionOffset = 0;
	private static readonly _PayloadLengthOffset = 4;
	private static readonly _NextHeaderOffset = 6;
	private static readonly _HopLimitOffset = 7;
	private static readonly _SrcAddressOffset = 8;
	private static readonly _DstAddressOffset = 24;

	private static readonly _VersionLength = 1;
	private static readonly _PayloadLengthLength = 2;
	private static readonly _NextHeaderLength = 1;
	private static readonly _HopLimitLength = 1;
	private static readonly _SrcAddressLength = 16;
	private static readonly _DstAddressLength = 16;
	private static readonly _PacketLength = 40;

	packet: DataView;
	innerPacket: GenericPacket;

	constructor(packet: DataView, fc:FileContext) {

		super(packet, fc);
		this.packet = packet;
		fc.headers.push(this);
		this.innerPacket = IPv6Packet.nextPacket(packet, this.nextHeader, this.payloadLength, 40, fc);
	

		this.registerAddress(this.srcAddress.correctForm(), fc);
		if (this.srcAddress.correctForm() !== this.destAddress.correctForm()) {
			this.registerAddress(this.destAddress.correctForm(), fc);
		}
		
		this.registerProtocol(IPv6Packet.Name, fc);
	}

	get version() {
		return this.packet.getUint8(IPv6Packet._VersionOffset) >> 4;
	}

	get payloadLength() {
		return this.packet.getUint16(IPv6Packet._PayloadLengthOffset);
	}

	get nextHeader() {
		return this.packet.getUint8(IPv6Packet._NextHeaderOffset);
	}

	get hopLimit() {
		return this.packet.getUint8(IPv6Packet._HopLimitOffset);
	}

	get srcAddress() {
		const a = this.packet.buffer.slice(this.packet.byteOffset + IPv6Packet._SrcAddressOffset, this.packet.byteOffset + IPv6Packet._SrcAddressOffset + IPv6Packet._SrcAddressLength);
		const ua = new Uint8Array(a);
		const na = Array.from(ua);
		return Address6.fromByteArray(na);
	}

	get destAddress() {
		const a = this.packet.buffer.slice(this.packet.byteOffset + IPv6Packet._DstAddressOffset, this.packet.byteOffset + IPv6Packet._DstAddressOffset + IPv6Packet._DstAddressLength);
		const ua = new Uint8Array(a);
		const na = Array.from(ua);
		return Address6.fromByteArray(na);
	}

	static nextPacket(packet: DataView, nextHeader: number, payloadLength: number, headerLength: number, fc:FileContext): GenericPacket {
		switch (nextHeader) {
			case 0x0:
				return new IPv6HopByHop(
					new DataView(packet.buffer, packet.byteOffset + headerLength, payloadLength), fc
				);
				break;
			case 0x01:
				return new ICMPPacket(
					new DataView(packet.buffer, packet.byteOffset + headerLength, payloadLength), fc
				);
				break;
			case 0x06:
				return new TCPPacket(
					new DataView(packet.buffer, packet.byteOffset + headerLength, payloadLength), fc
				);
				break;
			case 0x11:
				return new UDPPacket(
					new DataView(packet.buffer, packet.byteOffset + headerLength, payloadLength), fc
				);
				break;
			case 0x3a:
				return new ICMPv6Packet(
					new DataView(packet.buffer, packet.byteOffset + headerLength, payloadLength), fc
				);
				break;
			default:
				const generic = new GenericPacket(
					new DataView(packet.buffer, packet.byteOffset + headerLength, payloadLength), fc
				);
				generic.registerProtocol(`Internet Protocol #${nextHeader}`, fc);
				
				return generic;
			}
	}

	get nextHeaderName():string {
		switch (this.nextHeader) {
			case 0x0:
				return "Hop-by-Hop Options Header";
			case 0x01:
				return "ICMP";
			case 0x06:
				return "TCP";
			case 0x11:
				return "UDP";
			case 0x3a:
				return "ICMPv6";
			default:
				return "Unknown";
		}
	}

	get toString() {
		return `IPv${this.version}, ${this.srcAddress.correctForm()} > ${this.destAddress.correctForm()}, (0x${this.nextHeader.toString(16)}), ${this.innerPacket.toString} `;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const element = new Node("Internet Protocol Version 6", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, IPv6Packet._PacketLength);
		element.children.push(new Node(`Version`, `${this.version}`, defaultState, byteOffset + IPv6Packet._VersionOffset, IPv6Packet._VersionLength));
		element.children.push(new Node(`Payload Length`, `${this.payloadLength}`, defaultState, byteOffset + IPv6Packet._PayloadLengthOffset, IPv6Packet._PayloadLengthLength));
		element.children.push(new Node(`Next Header`, `${this.nextHeaderName} (${this.nextHeader})`, defaultState, byteOffset + IPv6Packet._NextHeaderOffset, IPv6Packet._NextHeaderLength));
		element.children.push(new Node(`Hop Limit`, `${this.hopLimit}`, defaultState, byteOffset + IPv6Packet._HopLimitOffset, IPv6Packet._HopLimitLength));
		element.children.push(new Node(`Source Address`, `${this.srcAddress.correctForm()}`, defaultState, byteOffset + IPv6Packet._SrcAddressOffset, IPv6Packet._SrcAddressLength));
		element.children.push(new Node(`Destination Address`, `${this.destAddress.correctForm()}`, defaultState, byteOffset + IPv6Packet._DstAddressOffset, IPv6Packet._DstAddressLength));
		
		return [element].concat(this.innerPacket.getProperties);
	}
}

class IPv6HopByHop extends GenericPacket {
	private static readonly _HeaderLengthOffset = 1;
	private static readonly _NextHeaderOffset = 0;

	private static readonly _HeaderLengthLength = 1;
	private static readonly _NextHeaderLength = 1;
	
	innerPacket: GenericPacket;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.packet = packet;
		this.innerPacket = IPv6Packet.nextPacket(packet, this.nextHeader, packet.byteLength-this.headerLength, this.headerLength, fc);
	}

	get headerLength() {
		return this.packet.getUint8(1);
	}

	get actualHeaderLength() {
		return (this.headerLength + 1)*8;
	}

	get nextHeader() {
		return this.packet.getUint8(0);
	}

	get nextHeaderName():string {
		switch (this.nextHeader) {
			case 0x0:
				return "Hop-by-Hop Options Header";
			case 0x01:
				return "ICMP";
			case 0x06:
				return "TCP";
			case 0x11:
				return "UDP";
			case 0x3a:
				return "ICMPv6";
			default:
				return "Unknown";
		}
	}

	get toString(): string {
		return `(0x${this.nextHeader.toString(16)}), ${this.innerPacket.toString}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const element = new Node("IPv6 Hop-by-Hop Option", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.actualHeaderLength);
		element.children.push(new Node(`Next Header`, `${this.nextHeaderName} (${this.nextHeader})`, defaultState, byteOffset + IPv6HopByHop._NextHeaderOffset, IPv6HopByHop._NextHeaderLength));
		element.children.push(new Node(`Length`, `${this.headerLength} [${this.actualHeaderLength}]`, defaultState, byteOffset + IPv6HopByHop._HeaderLengthOffset, IPv6HopByHop._HeaderLengthLength));

		return [element].concat(this.innerPacket.getProperties);
	}
}

class IPv6Routing extends GenericPacket {
	innerPacket: GenericPacket;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.packet = packet;
		this.innerPacket = IPv6Packet.nextPacket(packet, this.nextHeader, packet.byteLength-this.headerLength, this.headerLength, fc);
	
	}

	get headerLength() {
		return (this.packet.getUint8(1) + 1)*8;
	}

	get nextHeader() {
		return this.packet.getUint8(0);
	}

	get toString(): string {
		return `(0x${this.nextHeader.toString(16)}), ${this.innerPacket.toString}`;
	}
}
