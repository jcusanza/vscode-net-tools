import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { EthernetPacket } from "./ether";
import { IPv6Packet } from './ipv6Packet';
import { IPv4Packet } from './ipv4Packet';

export class pppoedPacket extends GenericPacket {
	public static readonly Name = "PPPoE";
	private static readonly _VersionOffset = 0;
	private static readonly _TypeOffset = 0;
	private static readonly _CodeOffset = 1;
	private static readonly _SessionIdOffset = 2;
	private static readonly _LengthOffset = 4;

	private static readonly _VersionLength = 1;
	private static readonly _TypeLength = 1;
	private static readonly _CodeLength = 1;
	private static readonly _SessionIdLength = 2;
	private static readonly _LengthLength = 2;
	private static readonly _PacketLength = 6;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(pppoedPacket.Name, fc);
	}

	get Version():number {
		return this.packet.getUint8(pppoedPacket._VersionOffset) >> 4 ;
	}
	get Type():number {
		return this.packet.getUint8(pppoedPacket._TypeOffset) & 0xF;
	}
	get Code():number {
		return this.packet.getUint8(pppoedPacket._CodeOffset);
	}
	get CodeName():string {
		switch (this.Code) {
			case 0x00: return "";
			case 0x09: return "Active Discovery Initiation (PADI)";
			case 0x07: return "Active Discovery Offer (PADO)";
			case 0x19: return "Active Discovery Request (PADR)";
			case 0xa7: return "Active Discovery Terminate (PADT)";
			case 0x65: return "Active Discovery Session-confirmation (PADS)";
			default: return `Unknown code (0x${this.Code.toString(16).padStart(2, "0")})`;
		}
	}
	get SessionId():number {
		return this.packet.getUint16(pppoedPacket._SessionIdOffset);
	}
	get Length():number {
		return this.packet.getUint16(pppoedPacket._LengthOffset);
	}
	
	get toString() {
		return `PPPoE ${this.CodeName}`;
	}

	get tags():pppoeTag[] {
		let i = 0;
		const ret:pppoeTag[] = [];
		while (i < this.Length) {
			ret.push(new pppoeTag(new DataView(this.packet.buffer, this.packet.byteOffset + pppoedPacket._PacketLength + i, this.packet.byteLength - pppoedPacket._PacketLength - i)));
			i += ret[ret.length-1].Length+4;
		}
		return ret;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;

		const element = new Node("PPP-over-Ethernet", `${this.CodeName}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, pppoedPacket._PacketLength + this.Length);
		element.children.push(new Node(`Version`, `${this.Version}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoedPacket._VersionOffset, pppoedPacket._VersionLength));
		element.children.push(new Node(`Type`, `${this.Type}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoedPacket._TypeOffset, pppoedPacket._TypeLength));
		element.children.push(new Node(`Code`, `${this.CodeName} (0x${this.Code.toString(16).padStart(2, "0")})`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoedPacket._CodeOffset, pppoedPacket._CodeLength));
		element.children.push(new Node(`Session ID`, `0x${this.SessionId.toString(16).padStart(2, "0")}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoedPacket._SessionIdOffset, pppoedPacket._SessionIdLength));
		element.children.push(new Node(`Payload Length`, `${this.Length}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoedPacket._LengthOffset, pppoedPacket._LengthLength));

		if (this.tags.length) {
			const e2 = new Node("PPPoE Tags", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset + pppoedPacket._PacketLength, this.Length);
			this.tags.forEach( t => {
				e2.children.push(t.getProperties);
			});	
			element.children.push(e2);
		}
		
		return [element];
	}
}

class pppoeTag {
	_packet: DataView;

	constructor(packet: DataView) {
		this._packet = packet;
	}
	get Type():number {
		return this._packet.getUint16(0);
	}
	get Length():number {
		let l = this._packet.getUint16(2);
		return l;
	}
	get Value() {
		switch (this.Type) {
			case 0x0000: 
				return "";
			case 0x0101:
				if (this.Length === 0) {
					return "(Any)"; 
				}
			case 0x0102: 
			case 0x0201:
			case 0x0202: 
			case 0x0203: 
				if (this.Length === 0 || this._packet.getUint8(4) === 0) {
					return "(Blank)"; 
				}
				else 
				{
					const decoder = new TextDecoder('utf-8');
					return decoder.decode(new DataView(this._packet.buffer, this._packet.byteOffset + 4, this.Length));
				}
			case 0x0103: 
			case 0x0104: 
			case 0x0105: 
			case 0x0110: 
			default: 
				let ret = "";
				for (let i = 0; i < this._packet.byteLength && i < this.Length; i++) {
					ret += this._packet.getUint8(i+4).toString(16).padStart(2, "0") + " ";
				}
				return ret.trimEnd();
		}
	}
	get TypeName():string{
		switch (this.Type) {
			case 0x0000: return "End-Of-List";
			case 0x0101: return "Service-Name";
			case 0x0102: return "AC-Name";
			case 0x0103: return "Host-Uniq";
			case 0x0104: return "AC-Cookie";
			case 0x0105: return "Vendor-Specific";
			case 0x0110: return "Relay-Session-Id";
			case 0x0201: return "Service-Name-Error";
			case 0x0202: return "AC-System-Error";
			case 0x0203: return "Generic-Error";
			default: return `Unknown type (0x${this.Type.toString(16).padStart(2, "0")})`;
		}
	}
	get toString() {
		return `${this.TypeName}: ${this.Value}`;
	}

	get getProperties(): Node {
		return new Node(`${this.TypeName}`, `${this.Value}`, vscode.TreeItemCollapsibleState.None, this._packet.byteOffset, this.Length + 4);
	}
}

export class pppoePacket extends GenericPacket {
	public static readonly Name = "PPPoE";

	private static readonly _VersionOffset = 0;
	private static readonly _TypeOffset = 0;
	private static readonly _CodeOffset = 1;
	private static readonly _SessionIdOffset = 2;
	private static readonly _LengthOffset = 4;

	private static readonly _VersionLength = 1;
	private static readonly _TypeLength = 1;
	private static readonly _CodeLength = 1;
	private static readonly _SessionIdLength = 2;
	private static readonly _LengthLength = 2;
	private static readonly _PacketLength = 6;

	innerPacket: GenericPacket;
	
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(pppoePacket.Name, fc);
		this.innerPacket = EthernetPacket.processPayload(0x880b, new DataView(packet.buffer, packet.byteOffset + pppoePacket._PacketLength, packet.byteLength - pppoePacket._PacketLength), fc);
	}

	get Version():number {
		return this.packet.getUint8(pppoePacket._VersionOffset) >> 4 ;
	}
	get Type():number {
		return this.packet.getUint8(pppoePacket._TypeOffset) & 0xF;
	}
	get Code():number {
		return this.packet.getUint8(pppoePacket._CodeOffset);
	}
	get CodeName():string {
		switch (this.Code) {
			case 0x00: return "Session Data";
			default: return `Unknown code (0x${this.Code.toString(16).padStart(2, "0")})`;
		}
	}
	get SessionId():number {
		return this.packet.getUint16(pppoePacket._SessionIdOffset);
	}
	get Length():number {
		return this.packet.getUint16(pppoePacket._LengthOffset);
	}
	
	get toString() {
		return `${this.innerPacket.toString}`;
	}

	get getProperties(): Node[] {
		const elements: Node[] = [];
		const byteOffset = this.packet.byteOffset;
		const element = new Node("PPP-over-Ethernet Session", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, pppoePacket._PacketLength);
		element.children.push(new Node(`Version`, `${this.Version}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoePacket._VersionOffset, pppoePacket._VersionLength));
		element.children.push(new Node(`Type`, `${this.Type}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoePacket._TypeOffset, pppoePacket._TypeLength));
		element.children.push(new Node(`Code`, `${this.CodeName} (0x${this.Code.toString(16).padStart(2, "0")})`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoePacket._CodeOffset, pppoePacket._CodeLength));
		element.children.push(new Node(`Session ID`, `0x${this.SessionId.toString(16).padStart(2, "0")}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoePacket._SessionIdOffset, pppoePacket._SessionIdLength));
		element.children.push(new Node(`Payload Length`, `${this.Length}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppoePacket._LengthOffset, pppoePacket._LengthLength));
		elements.push(element);
		return elements.concat(this.innerPacket.getProperties);
	}
}

export class pppPacket extends GenericPacket {
	public static readonly Name = "PPP";
	innerPacket: GenericPacket;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		fc.headers.push(this);

		const payload = new DataView(packet.buffer, packet.byteOffset + 2, packet.byteLength - 2)
		switch (this.Protocol) {
			case 0x0021:
				this.innerPacket = new IPv4Packet(payload, fc);
				return;
			case 0x0057:
				this.innerPacket = new IPv6Packet(payload, fc);
				return;
			case 0x8021:
				this.innerPacket = new pppIPControlPacket(payload, fc);
				return;
			case 0x8057:
				this.innerPacket = new pppIPv6ControlPacket(payload, fc);
				return;
			case 0xc021:
				this.innerPacket = new pppLinkControlPacket(payload, fc);
				return;
			default:
				this.innerPacket = new GenericPacket(payload, fc);
				this.innerPacket.registerProtocol(`PPP #${this.Protocol} (0x${this.Protocol.toString(16).padStart(4, "0")})`, fc);
				return;
		}
	}

	get Protocol():number {
		return this.packet.getUint16(0);
	}

	get toString() {
		return `${this.innerPacket.toString}`;
	}

	get getProperties(): Node[] {
		const elements: Node[] = [];
		const byteOffset = this.packet.byteOffset;
		const element = new Node("Point-to-Point Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, 2);
		element.children.push(new Node(`Protocol`, `${EthernetPacket.namePayload(this.Protocol)} (0x${this.Protocol.toString(16).padStart(4, "0")})`, vscode.TreeItemCollapsibleState.None, byteOffset, 2));
		elements.push(element);
		return elements.concat(this.innerPacket.getProperties);
	}
}


export class pppLinkControlPacket extends GenericPacket {
	public static readonly Name = "PPP-LCP";
	private static readonly _CodeOffset = 0;
	private static readonly _IdentifierOffset = 1;
	private static readonly _LengthOffset = 2;

	private static readonly _CodeLength = 1;
	private static readonly _IdentifierLength = 1;
	private static readonly _LengthLength = 2;
	private static readonly _PacketLength = 4;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		fc.headers.push(this);
	}

	get Code():number {
		return this.packet.getUint8(pppLinkControlPacket._CodeOffset);
	}
	get CodeName():string {
		switch (this.Code) {
			case 1:  return "Configure-Request";
			case 2:  return "Configure-Ack";
			case 3:  return "Configure-Nak";
			case 4:  return "Configure-Reject";
			case 5:  return "Terminate-Request";
			case 6:  return "Terminate-Ack";
			case 7:  return "Code-Reject";
			case 8:  return "Protocol-Reject";
			case 9:  return "Echo-Request";
			case 10: return "Echo-Reply";
			case 11: return "Discard-Request";
			default: return `Unknown code (0x${this.Code.toString(16).padStart(2, "0")})`;
		}
	}
	get Identifier():number {
		return this.packet.getUint8(pppLinkControlPacket._IdentifierOffset);
	}
	get Length():number {
		return this.packet.getUint16(pppLinkControlPacket._LengthOffset);
	}

	get toString() {
		return `${this.CodeName}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const element = new Node("PPP Link Control Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, pppLinkControlPacket._PacketLength + this.Length);
		element.children.push(new Node(`Code`, `${this.CodeName} (${this.Code})`, vscode.TreeItemCollapsibleState.None, byteOffset + pppLinkControlPacket._CodeOffset, pppLinkControlPacket._CodeLength));
		element.children.push(new Node(`Identifier`, `${this.Identifier}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppLinkControlPacket._IdentifierOffset, pppLinkControlPacket._IdentifierLength));
		element.children.push(new Node(`Length`, `${this.Length}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppLinkControlPacket._LengthOffset, pppLinkControlPacket._LengthLength));

		return [element];
	}
}

export class pppIPControlPacket extends GenericPacket {
	public static readonly Name = "PPP-IPCP";
	private static readonly _CodeOffset = 0;
	private static readonly _IdentifierOffset = 1;
	private static readonly _LengthOffset = 2;

	private static readonly _CodeLength = 1;
	private static readonly _IdentifierLength = 1;
	private static readonly _LengthLength = 2;
	private static readonly _PacketLength = 4;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		fc.headers.push(this);
	}

	get Code():number {
		return this.packet.getUint8(pppIPControlPacket._CodeOffset);
	}
	get CodeName():string {
		switch (this.Code) {
			case 1:  return "Configure-Request";
			case 2:  return "Configure-Ack";
			case 3:  return "Configure-Nak";
			case 4:  return "Configure-Reject";
			case 5:  return "Terminate-Request";
			case 6:  return "Terminate-Ack";
			case 7:  return "Code-Reject";
			case 8:  return "Protocol-Reject";
			case 9:  return "Echo-Request";
			case 10: return "Echo-Reply";
			case 11: return "Discard-Request";
			default: return `Unknown code (0x${this.Code.toString(16).padStart(2, "0")})`;
		}
	}
	get Identifier():number {
		return this.packet.getUint8(pppIPControlPacket._IdentifierOffset);
	}
	get Length():number {
		return this.packet.getUint16(pppIPControlPacket._LengthOffset);
	}

	get toString() {
		return `${this.CodeName}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const element = new Node("PPP IP Control Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, pppIPControlPacket._PacketLength + this.Length);
		element.children.push(new Node(`Code`, `${this.CodeName} (${this.Code})`, vscode.TreeItemCollapsibleState.None, byteOffset + pppIPControlPacket._CodeOffset, pppIPControlPacket._CodeLength));
		element.children.push(new Node(`Identifier`, `${this.Identifier}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppIPControlPacket._IdentifierOffset, pppIPControlPacket._IdentifierLength));
		element.children.push(new Node(`Length`, `${this.Length}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppIPControlPacket._LengthOffset, pppIPControlPacket._LengthLength));

		return [element];
	}
}

export class pppIPv6ControlPacket extends GenericPacket {
	public static readonly Name = "PPP-IPv6CP";
	private static readonly _CodeOffset = 0;
	private static readonly _IdentifierOffset = 1;
	private static readonly _LengthOffset = 2;

	private static readonly _CodeLength = 1;
	private static readonly _IdentifierLength = 1;
	private static readonly _LengthLength = 2;
	private static readonly _PacketLength = 4;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		fc.headers.push(this);
	}

	get Code():number {
		return this.packet.getUint8(pppIPv6ControlPacket._CodeOffset);
	}
	get CodeName():string {
		switch (this.Code) {
			case 1:  return "Configure-Request";
			case 2:  return "Configure-Ack";
			case 3:  return "Configure-Nak";
			case 4:  return "Configure-Reject";
			case 5:  return "Terminate-Request";
			case 6:  return "Terminate-Ack";
			case 7:  return "Code-Reject";
			case 8:  return "Protocol-Reject";
			case 9:  return "Echo-Request";
			case 10: return "Echo-Reply";
			case 11: return "Discard-Request";
			default: return `Unknown code (0x${this.Code.toString(16).padStart(2, "0")})`;
		}
	}
	get Identifier():number {
		return this.packet.getUint8(pppIPv6ControlPacket._IdentifierOffset);
	}
	get Length():number {
		return this.packet.getUint16(pppIPv6ControlPacket._LengthOffset);
	}

	get toString() {
		return `${this.CodeName}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const element = new Node("PPP IPv6 Control Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, pppIPv6ControlPacket._PacketLength + this.Length);
		element.children.push(new Node(`Code`, `${this.CodeName} (${this.Code})`, vscode.TreeItemCollapsibleState.None, byteOffset + pppIPv6ControlPacket._CodeOffset, pppIPv6ControlPacket._CodeLength));
		element.children.push(new Node(`Identifier`, `${this.Identifier}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppIPv6ControlPacket._IdentifierOffset, pppIPv6ControlPacket._IdentifierLength));
		element.children.push(new Node(`Length`, `${this.Length}`, vscode.TreeItemCollapsibleState.None, byteOffset + pppIPv6ControlPacket._LengthOffset, pppIPv6ControlPacket._LengthLength));

		return [element];
	}
}