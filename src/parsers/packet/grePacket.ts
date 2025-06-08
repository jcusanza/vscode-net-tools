import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { EthernetPacket } from "./ether";

export class grePacket extends GenericPacket {
    public static readonly Name = "GRE";

    innerPacket: GenericPacket;
    private _lines:string[] = [];

    private static readonly _FlagsOffset = 0;
    private static readonly _Reserved0Offset = 0;
    private static readonly _VerOffset = 1;
    private static readonly _ProtocolTypeOffset = 2;
    private static readonly _ChecksumOffset = 3;
	private static readonly _Reserved1Offset = 5;
	private static readonly _PayloadOffset = 8;

    private static readonly _FlagsLength = 1;
    private static readonly _Reserved0Length = 2;
    private static readonly _VerLength = 1;
    private static readonly _ProtocolTypeLength = 2;
    private static readonly _ChecksumLength = 2;
	private static readonly _Reserved1Length = 2;
	private static readonly _PayloadLength = 2;

    constructor(packet: DataView, fc:FileContext) {
        super(packet, fc);
        this.registerProtocol(grePacket.Name, fc);
        fc.headers.push(this);
		console.log(`Protocol Type: 0x${this.protocolType.toString(16).padStart(4, "0")} ${this.checksumPresent}`);
        let payloadStart: number = 4;
        if (this.checksumPresent) {
            payloadStart += 4;
        }
        if (this.keyPresent) {
            payloadStart += 4;
        }
        if (this.sequencePresent) {
            payloadStart += 4;
        }
        this.innerPacket = EthernetPacket.processPayload(this.protocolType, new DataView(packet.buffer, packet.byteOffset + payloadStart, packet.byteLength - payloadStart), fc);
    }

    get checksumPresent():boolean {
        return (this.packet.getUint8(grePacket._FlagsOffset) & 0x80) !== 0;
    }
    get keyPresent():boolean {
        return (this.packet.getUint8(grePacket._FlagsOffset) & 0x20) !== 0;
    }
    get sequencePresent():boolean {
        return (this.packet.getUint8(grePacket._FlagsOffset) & 0x10) !== 0;
    }
    get reserved0():number {
        return (this.packet.getUint16(grePacket._Reserved0Offset) >> 3) & 0xFFF;
    }
    get ver():number {
        return this.packet.getUint8(grePacket._VerOffset) & 0x7;
    }
    get protocolType():number {
        return this.packet.getUint16(grePacket._ProtocolTypeOffset);
    }

    get checksum() {
        return this.packet.getUint16(grePacket._ChecksumOffset);
    }

	get reserved1() {
        return this.packet.getUint16(grePacket._Reserved1Offset);
    }

    get key() {
        if (!this.keyPresent) {
            return 0;
        }
        const keyOffset = this.checksumPresent ? 8 : 4;
        return this.packet.getUint32(keyOffset);
    }

    get sequence() {
        if (!this.sequencePresent) {
            return 0;
        }
        let sequenceOffset = 4;
        if (this.checksumPresent) {
            sequenceOffset += 4;
        }
        if (this.keyPresent) {
            sequenceOffset += 4;
        }
        return this.packet.getUint32(sequenceOffset);
    }

    get toString() {
        return `GRE (0x${this.protocolType.toString(16).padStart(4, "0")}) ${this.innerPacket.toString}`;
    }

    get getProperties(): Node[] {
        const byteOffset = this.packet.byteOffset;
        const defaultState = vscode.TreeItemCollapsibleState.None;
        const protocolName = this.protocolType ? EthernetPacket.namePayload(this.protocolType) : 'Possible GRE Keepalive Packet';

        const elements: Node[] = [];
        let greLength = 4;
        if (this.checksumPresent) {
            greLength += 4;
        }
        if (this.keyPresent) {
            greLength += 4;
        }
        if (this.sequencePresent) {
            greLength += 4;
        }

        let e = new Node("Generic Routing Encapsulation (GRE)", `${protocolName}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, greLength);
        e.children.push(new Node("Protocol Type", `${protocolName} (0x${this.protocolType.toString(16).padStart(4, "0")})`, defaultState, byteOffset + grePacket._ProtocolTypeOffset, grePacket._ProtocolTypeLength));
        if (this.checksumPresent) {
            e.children.push(new Node("Checksum", `0x${this.checksum.toString(16).padStart(4, "0")}`, defaultState, byteOffset + grePacket._ChecksumOffset, grePacket._ChecksumLength));
        }
        if (this.keyPresent) {
            e.children.push(new Node("Key", `${this.key} (0x${this.key.toString(16).padStart(8, "0")})`, defaultState, this.checksumPresent ? byteOffset + grePacket._ChecksumOffset + 5 : byteOffset + grePacket._ChecksumOffset + 1, 4));
        }
        if (this.sequencePresent) {
            let sequenceOffset = byteOffset + 4;
            if (this.checksumPresent) {
                sequenceOffset += 4;
            }
            if (this.keyPresent) {
                sequenceOffset += 4;
            }
            e.children.push(new Node("Sequence", `${this.sequence} (0x${this.sequence.toString(16).padStart(8, "0")})`, defaultState, sequenceOffset, 4));
        }
        elements.push(e);
        return elements.concat(this.innerPacket.getProperties);
    }
}