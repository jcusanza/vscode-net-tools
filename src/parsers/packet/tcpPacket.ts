import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { DNSPacket } from "./dnsPacket";
import { HTTPPacket } from "./httpPacket";
import { TLSPacket } from "./tlsPacket";

export class TCPPacket extends GenericPacket {
	public static readonly Name = "TCP";

	private static readonly _srcPortOffset = 0;
	private static readonly _destPortOffset = 2;
	private static readonly _seqNumOffset = 4;
	private static readonly _ackNumOffset = 8;
	private static readonly _dataOffsetOffset = 12;
	private static readonly _ReservedOffset = 12;
	private static readonly _FlagsOffset = 13;
	private static readonly _WindowOffset = 14;
	private static readonly _ChecksumOffset = 16;
	private static readonly _UrgentPointerOffset = 18;
	private static readonly _OptionsOffset = 20;

	private static readonly _srcPortLength = 2;
	private static readonly _destPortLength = 2;
	private static readonly _seqNumLength = 4;
	private static readonly _ackNumLength = 4;
	private static readonly _dataOffsetLength = 1;
	private static readonly _ReservedLength = 1;
	private static readonly _FlagsLength = 1;
	private static readonly _WindowLength = 2;
	private static readonly _ChecksumLength = 2;
	private static readonly _UrgentPointerLength = 2;
	
	innerPacket?: GenericPacket;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		
		const dv = new DataView(packet.buffer, packet.byteOffset + this.dataOffset*4, packet.byteLength - this.dataOffset*4);
		fc.headers.push(this);

		if (dv.byteLength > 0) {
			if(this.destPort === 53 || this.srcPort === 53) {
				this.innerPacket = new DNSPacket(dv, fc);
			} else if(this.destPort === 80 || this.srcPort === 80) {
				this.innerPacket = new HTTPPacket(dv, fc);
			} else if(this.destPort === 443 || this.srcPort === 443) {
				this.innerPacket = TLSPacket.CreateTLSPacket(dv, fc);
			} else {
				this.innerPacket = new GenericPacket(dv, fc);
			}
		}
		
		
		this.registerProtocol(TCPPacket.Name, fc);

	}

	get srcPort() {
		return this.packet.getUint16(TCPPacket._srcPortOffset);
	}

	get destPort() {
		return this.packet.getUint16(TCPPacket._destPortOffset);
	}

	get seqNum() {
		return this.packet.getUint32(TCPPacket._seqNumOffset);
	}

	get ackNum() {
		return this.packet.getUint32(TCPPacket._ackNumOffset);
	}

	get dataOffset() {
		return this.packet.getUint8(TCPPacket._dataOffsetOffset) >> 4;
	}

	get reserved() {
		return (this.packet.getUint16(TCPPacket._ReservedOffset) >> 6) & 0x3f;
	}
	
	get cwr(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x80) !== 0;
	}

	get ece(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x40) !== 0;
	}

	get urg(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x20) !== 0;
	}

	get ack(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x10) !== 0;
	}

	get psh(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x8) !== 0;
	}

	get rst(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x4) !== 0;
	}

	get syn(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x2) !== 0;
	}

	get fin(): boolean {
		return (this.packet.getUint8(TCPPacket._FlagsOffset) & 0x1) !== 0;
	}

	get getFlags(): string {
		let buffer: string = "";
		if(this.urg) {
			buffer += "URG ";
		}
		if(this.syn) {
			buffer += "SYN ";
		}
		if(this.psh) {
			buffer += "PSH ";
		}
		if(this.fin) {
			buffer += "FIN ";
		}
		if(this.ack) {
			buffer += "ACK ";
		}
		if(this.rst) {
			buffer += "RST ";
		}
		if(this.cwr) {
			buffer += "CWR ";
		}
		if(this.ece) {
			buffer += "ECE ";
		}

		return buffer.trimEnd();
	}

	get window() {
		return this.packet.getUint16(TCPPacket._WindowOffset);
	}

	get checksum() {
		return this.packet.getUint16(TCPPacket._ChecksumOffset);
	}

	get urgentPointer() {
		return this.packet.getUint16(TCPPacket._UrgentPointerOffset);
	}
	get payloadLength() {
		return this.packet.byteLength - this.headerLength;
	}
	get headerLength() {
		return this.dataOffset * 4;
	}
	get options(): TCPOption[] {
		if (this.packet.byteLength <= TCPPacket._OptionsOffset) {
			return [];
		}
		
		if (this.headerLength <= TCPPacket._OptionsOffset) {
			return [];
		}
		
		let i = this.packet.byteOffset + TCPPacket._OptionsOffset;
		const options: TCPOption[] = [];
		try {
			while (i < this.headerLength + this.packet.byteOffset) {
				const option = TCPOption.create(new DataView(this.packet.buffer, i, this.packet.buffer.byteLength - i));
				if (option.length > 0) {
					i += option.length;
					options.push(option);
				} else {
					i += 1;
				}
			}
		} catch (e) {

		}
	
		return options;
	}

	get toString() {
		let flags = this.getFlags;
		let inner = "";
		let ack = "";

		if (flags.length) {
			flags = ` [${flags}]`;
		}
		if (this.innerPacket !== undefined && this.innerPacket.packet.byteLength) {
			inner = `, ` + this.innerPacket.toString;
		}
		if (this.ack) {
			ack = ` ack=${this.ackNum}`;
		}

		return `TCP ${this.srcPort} > ${this.destPort}${flags} Seq=${this.seqNum}${ack} Win=${this.window} Len=${this.payloadLength}${inner}`;
	}

	get getProperties(): Node[] {
		let byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const elements: Node[] = [];
		let e = new Node("Transmission Control Protocol", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.headerLength + this.packet.byteOffset);
		e.children.push(new Node("Source Port", `${this.srcPort}`, defaultState, byteOffset + TCPPacket._srcPortOffset, TCPPacket._srcPortLength));
		e.children.push(new Node("Destination Port", `${this.destPort}`, defaultState, byteOffset + TCPPacket._destPortOffset, TCPPacket._destPortLength));
		e.children.push(new Node("Sequence number", `${this.seqNum}`, defaultState, byteOffset + TCPPacket._seqNumOffset, TCPPacket._seqNumLength));
		e.children.push(new Node("Acknowledgement number", `${this.ackNum}`, defaultState, byteOffset + TCPPacket._ackNumOffset, TCPPacket._ackNumLength));
		e.children.push(new Node("Header Length", `${this.dataOffset * 4} bytes (${this.dataOffset})`, defaultState, byteOffset + TCPPacket._dataOffsetOffset, TCPPacket._dataOffsetLength));
		
		let e2 = new Node("Flags", `${this.getFlags}`, vscode.TreeItemCollapsibleState.Collapsed, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength);
		e2.children.push(new Node("Urgent", `${this.urg ? "Set (1)" : "Not set (0)"}`, defaultState, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength));
		e2.children.push(new Node("Acknowledgement", `${this.ack ? "Set (1)" : "Not set (0)"}`, defaultState, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength));
		e2.children.push(new Node("Push", `${this.psh ? "Set (1)" : "Not set (0)"}`, defaultState, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength));
		e2.children.push(new Node("Reset", `${this.rst ? "Set (1)" : "Not set (0)"}`, defaultState, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength));
		e2.children.push(new Node("Syn", `${this.syn ? "Set (1)" : "Not set (0)"}`, defaultState, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength));
		e2.children.push(new Node("Fin", `${this.fin ? "Set (1)" : "Not set (0)"}`, defaultState, byteOffset + TCPPacket._FlagsOffset, TCPPacket._FlagsLength));
		e.children.push(e2);

		e.children.push(new Node("Window", `${this.window}`, defaultState, byteOffset + TCPPacket._WindowOffset, TCPPacket._WindowLength));
		e.children.push(new Node("Checksum", `0x${this.checksum.toString(16)}`, defaultState, byteOffset + TCPPacket._ChecksumOffset, TCPPacket._ChecksumLength));
		e.children.push(new Node("Urgent Pointer", `${this.urgentPointer}`, defaultState, byteOffset + TCPPacket._UrgentPointerOffset, TCPPacket._UrgentPointerLength));

		if(this.options.length > 0) {
			byteOffset += TCPPacket._OptionsOffset;
			e2 = new Node("Options", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.headerLength - TCPPacket._OptionsOffset);
			this.options.forEach(item => {
				e2.children.push(new Node(item.toString, ``, defaultState, byteOffset, item.length));
				byteOffset += item.length;
			});
			e.children.push(e2);
		}

		elements.push(e);

		if (this.innerPacket !== undefined) {
			return elements.concat(this.innerPacket.getProperties);
		} else {
			return elements;
		}
	}
}

class TCPOption {
    optionData: DataView;
    length: number;
    code: number;

    constructor(dv: DataView, offset: number, length: number, code: number) {
        this.optionData = new DataView(dv.buffer, offset, length);
        this.length = length;
        this.code = code;
    }

    static create(dv: DataView): TCPOption {
        const type = dv.getUint8(0);
        switch (type) {
            case 0: // End of option list
                return new TCPOption(dv, 0, 0, 0);
            case 1:
                return new TCPOptionNOP(dv, 0, 1, 1);
            case 2:
                return new TCPOptionMSS(dv, dv.byteOffset + 2, dv.getUint8(1), 2);
            case 3:
                return new TCPOptionWindowScale(dv, dv.byteOffset + 2, dv.getUint8(1), 3);
            case 4:
                return new TCPOptionSACKPermitted(dv, dv.byteOffset + 2, dv.getUint8(1), 4);
            case 8:
                return new TCPOptionTimestamp(dv, dv.byteOffset + 2, dv.getUint8(1), 8);
            default:
                return new TCPOption(dv, dv.byteOffset + 2, dv.getUint8(1), type);
        }
    }

    get toString(): string {
        return `Option: ${this.code}, Length: ${this.length}`;
    }
}

class TCPOptionNOP extends TCPOption {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get toString(): string {
        return `No-Operation (${this.code})`;
    }
}

class TCPOptionMSS extends TCPOption {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get mss(): number {
        return this.optionData.getUint16(0);
    }

    get toString(): string {
        return `Maximum Segment Size (${this.code}) - MSS: ${this.mss}`;
    }
}

class TCPOptionWindowScale extends TCPOption {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get shiftCount(): number {
        return this.optionData.getUint8(0);
    }

    get toString(): string {
        return `Window Scale (${this.code}) - Shift Count: ${this.shiftCount}`;
    }
}

class TCPOptionSACKPermitted extends TCPOption {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get isPermitted(): boolean {
        return this.length === 2;
    }

    get toString(): string {
        return `SACK Permitted (${this.code}) - Permitted: ${this.isPermitted}`;
    }
}

class TCPOptionTimestamp extends TCPOption {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get timestamp(): number {
        return this.optionData.getUint32(0);
    }

    get echoReply(): number {
        return this.optionData.getUint32(4);
    }

    get toString(): string {
        return `Timestamp (${this.code}) - Timestamp Value: ${this.timestamp}, Timestamp Echo Reply: ${this.echoReply}`;
    }
}
