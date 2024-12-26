import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

const ARPOffset = {
	htype: 0,
	ptype: 2,
	HardwareAddressLength: 4,
	ProtocolAddressLength: 5,
	OPCode: 6,
	HardwareAddressSender: 8
} as const;

const ARPBytes = {
	htype: 2,
	ptype: 2,
	HardwareAddressLength: 1,
	ProtocolAddressLength: 1,
	OPCode: 2,
	FixedParameters: 8
} as const;

export class ARPPacket extends GenericPacket {
	public static readonly Name = "ARP";
	packet: DataView;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.packet = packet;

		this.registerAddress(this.protocolAddressSender, fc);
		if (this.protocolAddressSender !== this.protocolAddressTarget) {
			this.registerAddress(this.protocolAddressTarget, fc);
		}

		this.registerProtocol(ARPPacket.Name, fc);
	}

	get htype() {
		return this.packet.getUint16(ARPOffset.htype);
	}

	get htypeString() {
		switch (this.htype) {
			case 1:
				return "Ethernet";
			case 2:
				return "Experimental Ethernet";
			case 3:
				return "Amateur Radio AX.25";
			case 4:
				return "Proteon ProNET Token Ring";
			case 5:
				return "Chaos";
			case 6:
				return "IEEE 802 Networks";
			case 7:
				return "ARCNET";
			case 8:
				return "Hyperchannel";
			case 9:
				return "Lanstar";
			case 10:
				return "Autonet Short Address";
			case 11:
				return "LocalTalk";
			case 12:
				return "LocalNet";
			case 13:
				return "Ultra link";
			case 14:
				return "SMDS";
			case 15:
				return "Frame Relay";
			case 16:
				return "Asynchronous Transmission Mode";
			case 17:
				return "HDLC";
			case 18:
				return "Fibre Channel";
			case 19:
				return "Asynchronous Transmission Mode";
			case 20:
				return "Serial Line";
			case 21:
				return "Asynchronous Transmission Mode";
			default:
				return "Unknown network type";
		}
	}

	get ptype() {
		return this.packet.getUint16(ARPOffset.ptype);
	}

	get hardwareAddressLength() {
		return this.packet.getUint8(ARPOffset.HardwareAddressLength);
	}

	get protocolAddressLength() {
		return this.packet.getUint8(ARPOffset.ProtocolAddressLength);
	}

	get opcode() {
		return this.packet.getUint16(ARPOffset.OPCode);
	}

	get hardwareAddressSender(): string {
		let ret = "";
		for (let i = ARPOffset.HardwareAddressSender; i < ARPOffset.HardwareAddressSender + this.hardwareAddressLength - 1; i++) {
			ret += this.packet.getUint8(i).toString(16).padStart(2, "0") + ":";
		}
		ret += this.packet
			.getUint8(ARPOffset.HardwareAddressSender + this.hardwareAddressLength - 1)
			.toString(16)
			.padStart(2, "0");
		return ret;
	}

	get protocolAddressSender(): string {
		let ret = "";
		for (
			let i = ARPOffset.HardwareAddressSender + this.hardwareAddressLength;
			i < this.protocolAddressLength + this.hardwareAddressLength + ARPOffset.HardwareAddressSender - 1;
			i++
		) {
			ret += this.packet.getUint8(i) + ".";
		}
		ret += this.packet.getUint8(this.protocolAddressLength + ARPOffset.HardwareAddressSender + this.hardwareAddressLength - 1);
		return ret;
	}

	get hardwareAddressTarget(): string {
		let ret = "";
		for (
			let i = ARPOffset.HardwareAddressSender + this.hardwareAddressLength + this.protocolAddressLength;
			i < this.protocolAddressLength + this.hardwareAddressLength * 2 + ARPOffset.HardwareAddressSender - 1;
			i++
		) {
			ret += this.packet.getUint8(i).toString(16).padStart(2, "0") + ":";
		}
		ret += this.packet
			.getUint8(this.protocolAddressLength + ARPOffset.HardwareAddressSender + this.hardwareAddressLength * 2 - 1)
			.toString(16)
			.padStart(2, "0");
		return ret;
	}

	get protocolAddressTarget(): string {
		let ret = "";
		for (
			let i = ARPOffset.HardwareAddressSender + this.hardwareAddressLength * 2 + this.protocolAddressLength;
			i < this.protocolAddressLength * 2 + this.hardwareAddressLength * 2 + ARPOffset.HardwareAddressSender - 1;
			i++
		) {
			ret += this.packet.getUint8(i) + ".";
		}
		ret += this.packet.getUint8(
			this.protocolAddressLength * 2 + ARPOffset.HardwareAddressSender + this.hardwareAddressLength * 2 - 1,
		);
		return ret;
	}

	get toString() {
		let message = "";
		if (this.opcode === 1) {
			if (this.hardwareAddressTarget.toLowerCase() === 'ff:ff:ff:ff:ff:ff') {
				message = `Who has ${this.protocolAddressTarget}?`;
			} else if (this.hardwareAddressTarget.toLowerCase() === '00:00:00:00:00:00' && this.protocolAddressSender === "0.0.0.0") {
				message = `Who has ${this.protocolAddressTarget}? (ARP Probe)`;
			} else if (this.hardwareAddressTarget.toLowerCase() === '00:00:00:00:00:00' && this.protocolAddressSender === this.protocolAddressTarget) {
				message = `ARP Announcement for ${this.protocolAddressTarget}`;
			} else {
				message = `Who has ${this.protocolAddressTarget}? Tell ${this.protocolAddressSender}`;
			}
		} else {
			if (this.hardwareAddressTarget.toLowerCase() === 'ff:ff:ff:ff:ff:ff' && this.protocolAddressSender === this.protocolAddressTarget) {
				message = `Gratuitous ARP for ${this.protocolAddressSender} (Reply)`;
			} else {
				message = `${this.protocolAddressSender} is at ${this.hardwareAddressSender}`;
			}
		}
		return `ARP, ${message}`;
	}

	get getProperties(): Node[] {
		const byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const elements: Node[] = [];
		let e = new Node("Address Resolution Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.protocolAddressLength * 2 + this.hardwareAddressLength * 2 + ARPBytes.FixedParameters);
		e.children.push(new Node("Hardware type", `${this.htypeString} (${this.htype})`, defaultState, byteOffset + ARPOffset.htype, ARPBytes.htype));
		e.children.push(new Node("Protocol type", `IPv4 (0x${this.ptype.toString(16)})`, defaultState, byteOffset + ARPOffset.ptype, ARPBytes.ptype));
		e.children.push(new Node("Hardware size", this.hardwareAddressLength.toString(), defaultState, byteOffset + ARPOffset.HardwareAddressLength, ARPBytes.HardwareAddressLength));
		e.children.push(new Node("Protocol size", this.protocolAddressLength.toString(), defaultState, byteOffset + ARPOffset.ProtocolAddressLength, ARPBytes.ProtocolAddressLength));
		e.children.push(new Node("Opcode", `${this.opcode === 1 ? "request" : "reply"} (${this.opcode})`, defaultState, byteOffset + ARPOffset.OPCode, ARPBytes.OPCode));
		e.children.push(new Node("Sender MAC address", this.hardwareAddressSender, defaultState, byteOffset + ARPOffset.HardwareAddressSender, this.hardwareAddressLength));
		e.children.push(new Node("Sender IP address", this.protocolAddressSender, defaultState, byteOffset + ARPOffset.HardwareAddressSender + this.hardwareAddressLength, this.protocolAddressLength));
		e.children.push(new Node("Target MAC address", this.hardwareAddressTarget, defaultState, byteOffset + ARPOffset.HardwareAddressSender + this.hardwareAddressLength + this.protocolAddressLength, this.hardwareAddressLength));
		e.children.push(new Node("Target IP address", this.protocolAddressTarget, defaultState, byteOffset + ARPOffset.HardwareAddressSender + this.hardwareAddressLength*2 + this.protocolAddressLength, this.protocolAddressLength));

		elements.push(e);
		return elements;
	}
}


