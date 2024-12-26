import * as vscode from 'vscode';
import { Node } from "../../packetdetailstree";
import { GenericPacket } from "./genericPacket";
import { FileContext } from "../file/FileContext";

enum TLSContentTypes {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23
}

enum TLSHandshakeMessageTypes {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254 
}

export class TLSPacket extends GenericPacket {
	public static readonly Name = "TLS";

	static CreateTLSPacket(packet:DataView, fc:FileContext):GenericPacket {
        const contentType = packet.getUint8(0);

        switch (contentType) {
            case TLSContentTypes.change_cipher_spec:
                return new TLSChangeCipherSpec(packet, fc);
            case TLSContentTypes.alert:
                return new TLSAlert(packet, fc);
            case TLSContentTypes.handshake:
                const messageType = packet.getUint8(5);
                switch (messageType) {
                    case TLSHandshakeMessageTypes.client_hello: 
                        return new TLSClientHello(packet, fc);
                    case TLSHandshakeMessageTypes.server_hello:
                        return new TLSServerHello(packet, fc);
                    case TLSHandshakeMessageTypes.new_session_ticket:
                        return new TLSNewSessionTicket(packet, fc);
                    case TLSHandshakeMessageTypes.end_of_early_data:
                        return new TLSEndOfEarlyData(packet, fc);
                    case TLSHandshakeMessageTypes.encrypted_extensions:
                        return new TLSEncryptedExtensions(packet, fc);
                    case TLSHandshakeMessageTypes.certificate:
                        return new TLSCertificate(packet, fc);
                    case TLSHandshakeMessageTypes.certificate_request:
                        return new TLSCertificateRequest(packet, fc);
                    case TLSHandshakeMessageTypes.certificate_verify:
                        return new TLSCertificateVerify(packet, fc);
                    case TLSHandshakeMessageTypes.finished:
                        return new TLSFinished(packet, fc);
                    case TLSHandshakeMessageTypes.key_update:
                        return new TLSKeyUpdate(packet, fc);
                    case TLSHandshakeMessageTypes.message_hash:   
                        return new TLSMessageHash(packet, fc);
                }
            case TLSContentTypes.application_data:
                return new TLSApplicationData(packet, fc);
            default:
                return new TLSRecord(packet, fc);
        }
    }
}


// #region TLSRecord

export class TLSRecord extends GenericPacket {
    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
		this.registerProtocol(TLSPacket.Name, fc);
	}

    get ContentType(){
        return this.packet.getUint8(0);
    }

    get ProtocolVersion() {
        return this.packet.getUint16(1);
    }

    get length() {
        return this.packet.getUint16(3);
    }

    get toString() {
		return `TLS Record`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

// #region TLSChangeCipherSpec

export class TLSChangeCipherSpec extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `TLS Change Cipher Spec`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

// #region TLSApplicationData

export class TLSApplicationData extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get toString() {
		return `TLS Application Data`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

// #region TLSAlert

export class TLSAlert extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get AlertLevel(){
        return this.packet.getUint8(this.offset + 0);
    }

    get AlertDescription() {
        return this.packet.getUint8(this.offset + 1);
    }

    get toString() {
		return `TLS Alert`;
	}


	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

// #region TLSHandshake

export class TLSHandshake extends TLSRecord {
    private offset:number = 5;

    constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

    get MessageType(){
        return this.packet.getUint8(this.offset + 0);
    }

    get length() {
        return (this.packet.getUint8(this.offset + 1) << 16) & (this.packet.getUint8(this.offset + 2) << 8) & (this.packet.getUint8(this.offset + 3));
    }

    get toString() {
		return `TLS Handshake`;
	}


	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

// #region Handshake Messages


export class TLSClientHello extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Client Hello`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

export class TLSServerHello extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Server Hello`;
	}

	get getProperties(): Array<any> {
		const arr: Array<any> = [
            `*Transport Layer Security`,
        ];

		return arr;
	}
}

export class TLSNewSessionTicket extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS New Session Ticket`;
	}


	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

export class TLSEndOfEarlyData extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS End of Early Data`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

export class TLSEncryptedExtensions extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Encrypted Extensions`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}

}

export class TLSCertificate extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Certificate`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

export class TLSCertificateRequest extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Certificate Request`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

export class TLSCertificateVerify extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Certificate Verify`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

export class TLSFinished extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Finished`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

export class TLSKeyUpdate extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Key Update`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}

export class TLSMessageHash extends TLSHandshake {
	constructor(packet: DataView, fc:FileContext) {
		super(packet, fc);
	}

	get toString() {
		return `TLS Message Hash`;
	}

	get getProperties(): Node[] {
		const element = new Node("Transport Layer Security", ``, vscode.TreeItemCollapsibleState.Collapsed);
		return [element];
	}
}


