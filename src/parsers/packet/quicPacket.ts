import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

export class QUICPacket extends GenericPacket {
	public static readonly Name = "QUIC";

    static CreateQUICPacket(packet:DataView, fc:FileContext):GenericPacket {
		const isLongHeader:boolean = (packet.getUint8(0) & 0x80) !== 0;

        if (isLongHeader) {
            const version:number = packet.getUint32(1);

            if (version === 0) {
                return new QUICVersionNegotiationPacket(packet, fc);
            }
            const longPacketType:number = (packet.getUint8(0) >> 4) & 0x3;

            switch (longPacketType) {
                case 0x00:
                    return new QUICInitialPacket(packet, fc);
                case 0x01:
                    return new QUIC0RTTPacket(packet, fc);
                case 0x02:
                    return new QUICHandshakePacket(packet, fc);
                case 0x03:
                    return new QUICRetryPacket(packet, fc);
                default:
                    throw new Error("Impossible long packet type."); //longPacketType should only be two bits, so this should be impossible.
            }
        } else {
            return new QUIC1RTTPacket(packet, fc);
        }
    }
}

// #region Long

export class QUICLongPacket extends GenericPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
        this.registerProtocol(QUICPacket.Name, fc);
	}

	get HeaderForm() {
		return (this.packet.getUint8(0) >> 7) & 0x1;
	}
	get FixedBit() {
		return (this.packet.getUint8(0) >> 6) & 0x1;
	}
	get LongPacketType() {
		return (this.packet.getUint8(0) >> 4) & 0x3;
	}
	get Unused() {
		return (this.packet.getUint8(0)) & 0x15;
	}
	get Version() {
		return this.packet.getUint32(1);
	}
	get DstConnectionIdLength() {
		return this.packet.getUint8(5);
	}
	get DestConnectionId() {
        const start = this.packet.byteOffset + 6;
        const length = this.DstConnectionIdLength;
        const byteArray = new Uint8Array(this.packet.buffer, start, length); //TODO: deal with truncated packets
        return Array.from(byteArray)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
	}
	get SrcConnectionIdLength() {
        return this.packet.getUint8(6 + this.DstConnectionIdLength);
	}
	get SrcConnectionId() {
        const start = this.packet.byteOffset + 7 + this.DstConnectionIdLength;
        const length = this.SrcConnectionIdLength;
        const byteArray = new Uint8Array(this.packet.buffer, start, length); //TODO: deal with truncated packets
        return Array.from(byteArray)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
	}
	get PayloadStart() {
        return this.DstConnectionIdLength + this.SrcConnectionIdLength + 7;
	}
	get toString() {
		return `QUIC`;
	}

    get getProperties(): Node[] {
		const element = new Node("QUIC Header", ``, vscode.TreeItemCollapsibleState.Collapsed);
		element.children.push(new Node("Header form", `${this.HeaderForm}`));
		element.children.push(new Node("Fixed bit", `${this.FixedBit}`));
        element.children.push(new Node("Packet Type", `${this.LongPacketType}`));
        element.children.push(new Node("Reserved", `${this.Unused}`));
        //element.children.push(new Node("Packet Number Length", `${this.PacketNumberLength}`));
        element.children.push(new Node("Version", `${this.Version}`));
        element.children.push(new Node("Destination Connection ID Length", `${this.DstConnectionIdLength}`));
        if (this.DstConnectionIdLength) {
            element.children.push(new Node("Destination Connection ID", `${this.DestConnectionId}`));
        }
        element.children.push(new Node("Source Connection ID Length", `${this.SrcConnectionIdLength}`));
        if (this.SrcConnectionIdLength) {
            element.children.push(new Node("Source Connection ID", `${this.SrcConnectionId}`));
        }
		return [element];
	}
}


// #region VersionNegotiation

export class QUICVersionNegotiationPacket extends QUICLongPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get SupportedVersions():number[] {
        const v:number[] = [];
        for (let i = this.PayloadStart; i < this.packet.byteLength; i+=4) {
            v.push(this.packet.getUint32(i));
        }
        return v;
    }

    get toString() {
		return `QUIC Version Negotiation, Versions ${this.SupportedVersions.toString}`;
	}

    get getProperties(): Node[] {
		const element = new Node("QUIC Header", ``, vscode.TreeItemCollapsibleState.Collapsed);
		element.children.push(new Node("Header form", `${this.HeaderForm}`));
        element.children.push(new Node("Reserved", `${this.Unused}`));
        element.children.push(new Node("Version", `${this.Version}`));
        element.children.push(new Node("Destination Connection ID Length", `${this.DstConnectionIdLength}`));
        if (this.DstConnectionIdLength) {
            element.children.push(new Node("Destination Connection ID", `${this.DestConnectionId}`));
        }
        element.children.push(new Node("Source Connection ID Length", `${this.SrcConnectionIdLength}`));
        if (this.SrcConnectionIdLength) {
            element.children.push(new Node("Source Connection ID", `${this.SrcConnectionId}`));
        }
        element.children.push(new Node("Supported Version", `${this.SupportedVersions.toString}`));
		return [element];
	}
}

// #region Initial

export class QUICInitialPacket extends QUICLongPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}
    get PacketNumberLength() {
		return (this.packet.getUint8(0) & 0x3) + 1;
	}
	get TokenLength() {
        const enc = (this.packet.getUint8(super.PayloadStart) >> 6) & 0x3;
        switch (enc) {
            case 0:
                return this.packet.getUint8(super.PayloadStart) & 0x3F;
            case 1:
                return this.packet.getUint16(super.PayloadStart) & 0x3FFF;
            case 2:
                return this.packet.getUint32(super.PayloadStart) & 0x3FFFFFFF;
            case 3:
                const a = this.packet.getUint32(super.PayloadStart) & 0x3FFFFFFF;
                const b = this.packet.getUint32(super.PayloadStart+4);
                return (a << 30) + b;
        }
		return 0;
	}
    get TokenStart() {
        const enc = (this.packet.getUint8(super.PayloadStart) >> 6) & 0x3;
        switch (enc) {
            case 0:
                return super.PayloadStart + 1;
            case 1:
                return super.PayloadStart + 2;
            case 2:
                return super.PayloadStart + 4;
            case 3:
                return super.PayloadStart + 8;
        }
		return super.PayloadStart + 1;
    }
	get Token() {
        const start = this.packet.byteOffset + this.TokenStart;
        const length = this.TokenLength;
        const byteArray = new Uint8Array(this.packet.buffer, start, length); //TODO: deal with truncated packets
        return Array.from(byteArray)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
	}
    get Length() {
        const start = this.TokenStart + this.TokenLength;
        const enc = (this.packet.getUint8(start) >> 6) & 0x3;
        switch (enc) {
            case 0:
                return this.packet.getUint8(start) & 0x3F;
            case 1:
                return this.packet.getUint16(start) & 0x3FFF;
            case 2:
                return this.packet.getUint32(start) & 0x3FFFFFFF;
            case 3:
                const a = this.packet.getUint32(start) & 0x3FFFFFFF;
                const b = this.packet.getUint32(start+4);
                return (a << 30) + b;
        }
		return 0;
	}
    get PacketNumberStart() {
        const start = this.TokenStart + this.TokenLength;
        const enc = (this.packet.getUint8(start) >> 6) & 0x3;
        switch (enc) {
            case 0:
                return start + 1;
            case 1:
                return start + 2;
            case 2:
                return start + 4;
            case 3:
                return start + 8;
        }
		return super.PayloadStart + 1;
    }
    get PacketNumber() {
        const start = this.PacketNumberStart;
        switch (this.PacketNumberLength) {
            case 1:
                return this.packet.getUint8(start);
            case 2:
                return this.packet.getUint16(start);
            case 3:
                return this.packet.getUint32(start) >> 8;
            case 4:
                return this.packet.getUint32(start);
        }
		return 0;
	}

    get toString() {
        let ID = "";
        if (this.DstConnectionIdLength) {
            ID += `DCID=${this.DestConnectionId}, `;
        }
        if (this.SrcConnectionIdLength) {
            ID += `SCID=${this.SrcConnectionId}, `;
        }
		return `QUIC Initial, ${ID}`;
	}

    get getProperties(): Node[] {
		const element = new Node("QUIC Initial", ``, vscode.TreeItemCollapsibleState.Collapsed);
		element.children.push(new Node("Header form", `${this.HeaderForm}`));
        element.children = element.children.concat(super.getProperties);
        element.children.push(new Node("Token Length", `${this.TokenLength}`));
        if (this.TokenLength) {
            element.children.push(new Node("Token", `${this.Token}`));
        }
        element.children.push(new Node("Length", `${this.Length}`));
        element.children.push(new Node("Packet Number Length", `${this.PacketNumberLength}`));
        element.children.push(new Node("Packet Number", `${this.PacketNumber}`));

		return [element];
	}
}

// #region 0RTT

export class QUIC0RTTPacket extends QUICLongPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `QUIC 0RTT,`;
	}

}

// #region Handshake

export class QUICHandshakePacket extends QUICLongPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `QUIC Handshake,`;
	}

}

// #region Retry

export class QUICRetryPacket extends QUICLongPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `QUIC Retry,`;
	}

}

// #region 1RTT

export class QUIC1RTTPacket extends GenericPacket {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
        this.registerProtocol(QUICPacket.Name, fc);
	}

    get toString() {
		return `QUIC 1RTT`;
	}

    get getProperties(): Node[] {
		const element = new Node("QUIC 1RTT", ``, vscode.TreeItemCollapsibleState.Collapsed);

		return [element];
	}
}