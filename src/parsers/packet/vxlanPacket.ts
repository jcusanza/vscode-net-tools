import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { EthernetPacket } from "./ether";

export class vxlanPacket extends GenericPacket {
	public static readonly Name = "VXLAN";

	private static readonly _FlagsOffset = 0;
	private static readonly _VNIFlagOffset = 0;
	private static readonly _GBPFlagOffset = 0;
	private static readonly _DontLearnFlagOffset = 1;
	private static readonly _PolicyAppliedFlagOffset = 1;
	private static readonly _GroupPolicyIDOffset = 2;
	private static readonly _VNIOffset = 4;

	private static readonly _FlagsLength = 2;
	private static readonly _VNIFlagLength = 1;
	private static readonly _GBPFlagLength = 1;
	private static readonly _DontLearnFlagLength = 1;
	private static readonly _PolicyAppliedFlagLength = 1;
	private static readonly _GroupPolicyIDLength = 2;
	private static readonly _VNILength = 4;
	private static readonly _PacketLength = 8;

	innerPacket: GenericPacket;
	private _lines:string[] = [];

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(vxlanPacket.Name, fc);

		this.innerPacket = new EthernetPacket(new DataView(packet.buffer, packet.byteOffset + vxlanPacket._PacketLength, packet.byteLength - vxlanPacket._PacketLength), fc);
	}

	get VNIFlag():boolean {
		return (this.packet.getUint8(vxlanPacket._VNIFlagOffset) & 0x8) > 0;
	}
	get GBPFlag():boolean {
		return (this.packet.getUint8(vxlanPacket._GBPFlagOffset) & 0x80) > 0;
	}
	get DontLearnFlag():boolean {
		return (this.packet.getUint8(vxlanPacket._DontLearnFlagOffset) & 0x40) > 0;
	}
	get PolicyAppliedFlag():boolean {
		return (this.packet.getUint8(vxlanPacket._PolicyAppliedFlagOffset) & 0x8) > 0;
	}
	get Flags():number {
		return this.packet.getUint16(vxlanPacket._FlagsOffset);
	}
	get GroupPolicyID():number {
		return this.packet.getUint16(vxlanPacket._GroupPolicyIDOffset);
	}
	get VNI():number {
		return this.packet.getUint32(vxlanPacket._VNIOffset) >> 8;
	}

	get toString() {
		return `VXLAN ${this.VNI}: ${this.innerPacket.toString}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const elements: Node[] = [];
		let e = new Node("Virtual eXtensible Local Area Network", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, vxlanPacket._PacketLength);
		let e2 = new Node("Flags", `0x${this.Flags.toString(16).padStart(4, "0")}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset + vxlanPacket._FlagsOffset, vxlanPacket._FlagsLength);
		e2.children.push(new Node("GBP Extension", `${this.GBPFlag }`, defaultState, byteOffset + vxlanPacket._GBPFlagOffset, vxlanPacket._GBPFlagLength));
		e2.children.push(new Node("VXLAN Network ID (VNI)", `${this.VNIFlag }`, defaultState, byteOffset + vxlanPacket._VNIFlagOffset, vxlanPacket._VNIFlagLength));	
		e2.children.push(new Node("Don't Learn", `${this.DontLearnFlag }`, defaultState, byteOffset + vxlanPacket._DontLearnFlagOffset, vxlanPacket._DontLearnFlagLength));
		e2.children.push(new Node("Policy Applied", `${this.PolicyAppliedFlag }`, defaultState, byteOffset + vxlanPacket._PolicyAppliedFlagOffset, vxlanPacket._PolicyAppliedFlagLength));
		e.children.push(e2);
		e.children.push(new Node("Group Policy ID", `${this.GroupPolicyID}`, defaultState, byteOffset + vxlanPacket._GroupPolicyIDOffset, vxlanPacket._GroupPolicyIDLength));
		e.children.push(new Node("VXLAN Network Identifier (VNI)", `${this.VNI}`, defaultState, byteOffset + vxlanPacket._VNIOffset, vxlanPacket._VNILength));
		elements.push(e);
		return elements.concat(this.innerPacket.getProperties);
	}
}

