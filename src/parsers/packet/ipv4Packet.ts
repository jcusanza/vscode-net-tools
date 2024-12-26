import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";
import { ICMPPacket } from "./icmpPacket";
import { TCPPacket } from "./tcpPacket";
import { UDPPacket } from "./udpPacket";
import { igmpPacket } from "./igmpPacket";

const IPv4Offset = {
	Version: 0,
	IHL: 0,
	TypeOfService: 1,
	TotalLength: 2,
	Identification: 4,
	Flags: 6,
	FragmentOffset: 6,
	TimeToLive: 8,
	Protocol: 9,
	HeaderChecksum: 10,
	SrcAddress: 12,
	DstAddress: 16,
	Options: 20
} as const;

const IPv4Bytes = {
	Version: 1,
	IHL: 1,
	TypeOfService: 1,
	TotalLength: 2,
	Identification: 2,
	Flags: 1,
	FragmentOffset: 1,
	TimeToLive: 1,
	Protocol: 1,
	HeaderChecksum: 2,
	SrcAddress: 4,
	DstAddress: 4
} as const;

export class IPv4Packet extends GenericPacket {
	public static readonly Name = "IPv4";

	packet: DataView;
	innerPacket: GenericPacket;
	private isGeneric: boolean = false;

	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.packet = packet;
		const dv = new DataView(packet.buffer, packet.byteOffset + this.ihl*4, packet.byteLength - this.ihl*4);
		fc.headers.push(this);
		switch (this.protocol) {
			case 0x01:
				this.innerPacket = new ICMPPacket(dv, fc);
				break;
			case 0x02:
				this.innerPacket = new igmpPacket(dv, fc);
				break;
			case 0x06:
				this.innerPacket = new TCPPacket(dv, fc);
				break;
			case 0x11:
				this.innerPacket = new UDPPacket(dv, fc);
				break;
			default:
				this.innerPacket = new GenericPacket(dv, fc);
				this.isGeneric = true;
				this.registerProtocol(`Internet Protocol #${this.protocol}`, fc);
		}

		this.registerAddress(this.srcAddress, fc);
		if (this.srcAddress !== this.destAddress) {
			this.registerAddress(this.destAddress, fc);
		}

        this.registerProtocol(IPv4Packet.Name, fc);

	}

	get version() {
		return this.packet.getUint8(IPv4Offset.Version) >> 4;
	}

	get ihl() {
		return this.packet.getUint8(IPv4Offset.IHL) & 0xf;
	}

	get typeOfService() {
		return this.packet.getUint8(IPv4Offset.TypeOfService);
	}

	get totalLength() {
		return this.packet.getUint16(IPv4Offset.TotalLength);
	}
	get payloadLength() {
		return this.totalLength - this.ihl*4; 
	}
	get identification() {
		return this.packet.getUint16(IPv4Offset.Identification);
	}

	get flags() {
		return this.packet.getUint8(IPv4Offset.Flags) >> 5;
	}
	
	get fragmentOffset() {
		return this.packet.getUint16(IPv4Offset.FragmentOffset) & 0x1fff;
	}

	get timeToLive() {
		return this.packet.getUint8(IPv4Offset.TimeToLive);
	}

	get protocol() {
		return this.packet.getUint8(IPv4Offset.Protocol);
	}

	get headerChecksum() {
		return this.packet.getUint16(IPv4Offset.HeaderChecksum);
	}

	get srcAddress() {
		let ret = "";
		ret += this.packet.getUint8(IPv4Offset.SrcAddress) + ".";
		ret += this.packet.getUint8(IPv4Offset.SrcAddress+1) + ".";
		ret += this.packet.getUint8(IPv4Offset.SrcAddress+2) + ".";
		ret += this.packet.getUint8(IPv4Offset.SrcAddress+3);
		return ret;
	}

	get destAddress() {
		let ret = "";
		ret += this.packet.getUint8(IPv4Offset.DstAddress) + ".";
		ret += this.packet.getUint8(IPv4Offset.DstAddress+1) + ".";
		ret += this.packet.getUint8(IPv4Offset.DstAddress+2) + ".";
		ret += this.packet.getUint8(IPv4Offset.DstAddress+3);
		return ret;
	}

	get options(): IPv4Option[] {
        const options: IPv4Option[] = [];

        if (this.ihl * 4 <= IPv4Offset.Options) {
            return [];
        }

        let i = IPv4Offset.Options; 
        try {
            while (i < this.ihl * 4) {
                const option = IPv4Option.create(new DataView(this.packet.buffer, this.packet.byteOffset + i, this.packet.byteLength - i));
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
		if ( this.isGeneric) {
			return `IPv${this.version}, ${this.srcAddress} > ${this.destAddress}, (0x${this.protocol.toString(16).padStart(4, "0")}): ${this.innerPacket.toString}`;
		} 
		return `IPv${this.version}, ${this.srcAddress} > ${this.destAddress}, ${this.innerPacket.toString}`;
	}

	get protocolName():string {
		switch (this.protocol) {
			case 0x01:
				return "ICMP";
			case 0x02:
				return "IGMP";
			case 0x06:
				return "TCP";
			case 0x11:
				return "UDP";
			default:
				return "Unknown";
		}
	}

	get getProperties(): Node[] {
		let byteOffset = this.packet.byteOffset;
		const defaultState = vscode.TreeItemCollapsibleState.None;

		const element = new Node("Internet Protocol Version 4", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.ihl*4);
		element.children.push(new Node(`Version`, `${this.version}`, defaultState, byteOffset+IPv4Offset.Version, IPv4Bytes.Version));
		element.children.push(new Node(`Header Length`, `${this.ihl*4} bytes (${this.ihl})`, defaultState, byteOffset+IPv4Offset.IHL, IPv4Bytes.IHL));
		element.children.push(new Node(`Type of Service`, `${this.typeOfService}`, defaultState, byteOffset+IPv4Offset.TypeOfService, IPv4Bytes.TypeOfService));
		element.children.push(new Node(`Total Length`, `${this.totalLength}`, defaultState, byteOffset+IPv4Offset.TotalLength, IPv4Bytes.TotalLength));
		element.children.push(new Node(`Identification`, `0x${this.identification.toString(16)} (${this.identification})`, defaultState, byteOffset+IPv4Offset.Identification, IPv4Bytes.Identification));
		element.children.push(new Node(`Flags`, `0x${this.flags.toString(16)}`, defaultState, byteOffset+IPv4Offset.Flags, IPv4Bytes.Flags));
		element.children.push(new Node(`Fragment Offset`, `${this.fragmentOffset}`, defaultState, byteOffset+IPv4Offset.FragmentOffset, IPv4Bytes.FragmentOffset));
		element.children.push(new Node(`Time to Live`, `${this.timeToLive}`, defaultState, byteOffset+IPv4Offset.TimeToLive, IPv4Bytes.TimeToLive));
		element.children.push(new Node(`Protocol`, `${this.protocolName} (${this.protocol})`, defaultState, byteOffset+IPv4Offset.Protocol, IPv4Bytes.Protocol));
		element.children.push(new Node(`Header Checksum`, `${this.headerChecksum}`, defaultState, byteOffset+IPv4Offset.HeaderChecksum, IPv4Bytes.HeaderChecksum));
		element.children.push(new Node(`Source Address`, `${this.srcAddress}`, defaultState, byteOffset+IPv4Offset.SrcAddress, IPv4Bytes.SrcAddress));
		element.children.push(new Node(`Destination Address`, `${this.destAddress}`, defaultState, byteOffset+IPv4Offset.DstAddress, IPv4Bytes.DstAddress));
		
		if(this.options.length > 0) {
			byteOffset += IPv4Offset.Options;

			const element2 = new Node("Options", ``, vscode.TreeItemCollapsibleState.Collapsed, byteOffset, this.ihl*4 - IPv4Offset.Options);
			this.options.forEach(item => {
				element2.children.push(new Node(`${item.toString}`, ``, defaultState, byteOffset, item.length));
				byteOffset += item.length;
			});
			element.children.push(element2);
		}

		return [element].concat(this.innerPacket.getProperties);
	}
}

class IPv4Option {
    optionData: DataView;
    length: number;
    code: number;

    constructor(dv: DataView, offset: number, length: number, code: number) {
        this.optionData = new DataView(dv.buffer, offset, length);
        this.length = length;
        this.code = code;
    }

    static create(dv: DataView): IPv4Option {
		const type = dv.getUint8(0);
		switch (type) {
			case 0: // End of Option List
				return new IPv4Option(dv, 0, 0, 0);
			case 1:
				return new IPv4OptionNOP(dv, 0, 1, 1);
			case 2:
				return new IPv4OptionSecurity(dv, dv.byteOffset + 2, dv.getUint8(1), 2);
			case 3:
				return new IPv4OptionLooseSourceRouting(dv, dv.byteOffset + 2, dv.getUint8(1), 3);
			case 7:
				return new IPv4OptionRecordRoute(dv, dv.byteOffset + 2, dv.getUint8(1), 7);
			case 8:
				return new IPv4OptionStreamID(dv, dv.byteOffset + 2, dv.getUint8(1), 8);
			case 9:
				return new IPv4OptionStrictSourceRouting(dv, dv.byteOffset + 2, dv.getUint8(1), 9);
			case 68:
				return new IPv4OptionTimestamp(dv, dv.byteOffset + 2, dv.getUint8(1), 68);
			default:
				return new IPv4Option(dv, dv.byteOffset + 2, dv.getUint8(1), type);
		}
	}
	

    get toString(): string {
        return `Option: ${this.code}, Length: ${this.length}`;
    }
}

class IPv4OptionNOP extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get toString(): string {
        return `No-Operation (${this.code})`;
    }
}

class IPv4OptionRecordRoute extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get routeAddresses(): number[] {
        const addresses = [];
        for (let i = 0; i < this.length - 2; i += 4) {
            addresses.push(this.optionData.getUint32(i));
        }
        return addresses;
    }

    get toString(): string {
        return `Record Route Option (${this.code}) - Addresses: ${this.routeAddresses.join(', ')}`;
    }
}

class IPv4OptionSecurity extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get securityData(): Uint8Array {
        return new Uint8Array(this.optionData.buffer.slice(this.optionData.byteOffset, this.optionData.byteOffset + this.length));
    }

    get toString(): string {
        return `Security Option (${this.code}) - Data: ${Array.from(this.securityData).join(', ')}`;
    }
}

class IPv4OptionLooseSourceRouting extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get routeAddresses(): number[] {
        const addresses = [];
        for (let i = 0; i < this.length - 2; i += 4) {
            addresses.push(this.optionData.getUint32(i));
        }
        return addresses;
    }

    get toString(): string {
        return `Loose Source Routing Option (${this.code}) - Addresses: ${this.routeAddresses.join(', ')}`;
    }
}

class IPv4OptionStrictSourceRouting extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get routeAddresses(): number[] {
        const addresses = [];
        for (let i = 0; i < this.length - 2; i += 4) {
            addresses.push(this.optionData.getUint32(i));
        }
        return addresses;
    }

    get toString(): string {
        return `Strict Source Routing Option (${this.code}) - Addresses: ${this.routeAddresses.join(', ')}`;
    }
}

class IPv4OptionStreamID extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get streamID(): number {
        return this.optionData.getUint16(0);
    }

    get toString(): string {
        return `Stream ID Option (${this.code}) - StreamID: ${this.streamID}`;
    }
}

class IPv4OptionTimestamp extends IPv4Option {
    constructor(dv: DataView, offset: number, length: number, code: number) {
        super(dv, offset, length, code);
    }

    get timestamps(): { address: number, timestamp: number }[] {
        const records = [];
        for (let i = 0; i < this.length - 4; i += 8) {
            records.push({
                address: this.optionData.getUint32(i),
                timestamp: this.optionData.getUint32(i + 4)
            });
        }
        return records;
    }

    get toString(): string {
        return `Internet Timestamp Option (${this.code}) - Records: ${this.timestamps.map(rec => `{Address: ${rec.address}, Timestamp: ${rec.timestamp}}`).join(', ')}`;
    }
}


