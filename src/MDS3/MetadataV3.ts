import { MetadataV2 } from "../MDS2/MetadataV2";


type AAID = string;

type AAGUID = string;

type alternativeDescriptionsType = {
    [languageCode: string] : string;
}

type upvType = {
    major: number;
    minor: number;
}

type rgbPaletteEntry = {
    r: number
    g: number;
    b: number;
}

type tcDisplayPNGCharacteristicsType = {
    width: number;
    height: number;
    bitDepth: number;
    colorType: number;
    compression: number;
    filter: number;
    interlace: number;
    plte?: rgbPaletteEntry[];
};

type caDescType = {
    base: number;
    minLength: number;
    maxRetries?: number;
    blockSlowdown?: number;
};

type baDescType = {
    selfAttestedFRR?: number;
    selfAttestedFAR?: number;
    maxTemplates?: number;
    maxRetries?: number;
    blockSlowdown?: number;
};

type paDescType = {
    minComplexity: number;
    maxRetries?: number;
    blockSlowdown?: number;
}

type userVerificationDetailsType = {
    userVerificationMethod: number;
    caDesc?: caDescType;
    baDesc?: baDescType;
    paDesc?: paDescType;
};

type ecdaaTrustAnchorsType = {
    X: string;
    Y: string;
    c: string;
    sx: string;
    sy: string;
    G1Curve: string;
};

type supportedExtensionsType = {
    id: string;
    tag?: number;
    data?: string;
    fail_if_unknown: boolean;
};

type option = {
    plat: boolean;
    rk: boolean;
    clientPin: boolean;
    up: boolean;
    uv: boolean;
}

type AuthenticatorGetInfo = {
    versions: string[];
    extensions?: string[];
    aaguid: string;
    options?: option;
    maxMsgSize?: number;
    pinProtocols?: number[]
}

enum authAlgorithm {
    'secp256r1_ecdsa_sha256_raw' = 1,
    'secp256r1_ecdsa_sha256_der',
    'rsassa_pss_sha256_raw',
    'rsassa_pss_sha256_der',
    'secp256k1_ecdsa_sha256_raw',
    'secp256k1_ecdsa_sha256_der',
    'sm2_sm3_raw',
    'rsa_emsa_pkcs1_sha256_raw',
    'rsa_emsa_pkcs1_sha256_der',
    'rsassa_pss_sha384_raw',
    'rsassa_pss_sha512_raw',
    'rsassa_pkcsv15_sha256_raw',
    'rsassa_pkcsv15_sha384_raw',
    'rsassa_pkcsv15_sha512_raw',
    'rsassa_pkcsv15_sha1_raw',
    'secp384r1_ecdsa_sha384_raw',
    'secp512r1_ecdsa_sha256_raw',
    'ed25519_eddsa_sha512_raw'
};

enum PKAlgAndEncodings {
    'ecc_x962_raw' = 256,
    'ecc_x962_der',
    'rsa_2048_raw',
    'rsa_2048_der',
    'cose'
};

enum attestations {
    'basic_full' = 15879,
    'basic_surrogate',
    'ecdaa',
    'attca'
};

enum KProtection {
    'software' = 1,
    'hardware' = 2,
    'tee' = 4,
    'secure_element' = 8,
    'remote_handle' = 16
};

enum matcher {
    'software' = 1,
    'tee' = 2,
    'on_chip' = 4
};

enum attachmentHintValues {
    'internal' = 1,
    'external' = 2,
    'wired' = 4,
    'wireless' = 8,
    'nfc' = 16,
    'bluetooth' = 32,
    'network' = 64,
    'ready' = 128,
    'wifi_direct' = 256
};

enum tcDisplayValues {
    'any' = 1,
    'privileged_software' = 2,
    'tee' = 4,
    'hardware' = 8,
    'remote' = 16
};

enum userVerificationValues {
    'presence_internal' = 1,
    'fingerprint_internal' = 2,
    'passcode_internal' = 4,
    'voiceprint_internal' = 8,
    'faceprint_internal' = 16,
    'location_internal' = 32,
    'eyeprint_internal' = 64,
    'pattern_internal' = 128,
    'handprint_internal' = 256,
    'passcode_external' = 2048,
    'pattern_external' = 4096,
    'none' = 512,
    'all' = 1024
};

class MetadataV3 {
    private constructor() {}

    public static initialize<T extends MetadataV3>(data: T): MetadataV3 {
        const result = new MetadataV3();
        const dataJson = JSON.stringify(data);
        Object.assign(result, JSON.parse(dataJson));
        return result;
    }

    public static ConverterFromV2toV3(metadataV2: MetadataV2): MetadataV3 {
        let metadataV3 = new MetadataV3();

        if(metadataV2.getLegalHeader() !== undefined) {
            metadataV3.setLegalHeader(metadataV2.getLegalHeader()!)
        }

        if(metadataV2.getAAID() !== undefined) {
            metadataV3.setLegalHeader(metadataV2.getAAID()!)
        }

        if(metadataV2.getAAGUID() !== undefined) {
            metadataV3.setAAGUID(metadataV2.getAAGUID()!)
        }

        if(metadataV2.getAttestationCertificateKeyIdentifiers() !== undefined) {
            metadataV3.setAttestationCertificateKeyIdentifiers(metadataV2.getAttestationCertificateKeyIdentifiers()!)
        }

        if(metadataV2.getDescription() !== undefined) {
            metadataV3.setDescription(metadataV2.getDescription()!)
        }

        if(metadataV2.getAlternativeDescriptions() !== undefined) {
            metadataV3.setAlternativeDescriptions(metadataV2.getAlternativeDescriptions()!)
        }

        if(metadataV2.getAuthenticatorVersion() !== undefined) {
            metadataV3.setAuthenticatorVersion(metadataV2.getAuthenticatorVersion()!)
        }

        if(metadataV2.getProtocolFamily() === undefined) {
            switch(metadataV2.getAssertionScheme()) {
                case 'UAFV1TLV': {
                    metadataV3.setProtocolFamily('uaf');
                    break;
                }
                case 'U2FV1BIN': {
                    metadataV3.setProtocolFamily('u2f');
                    break;
                }
                case 'FIDOV2': {
                    metadataV3.setProtocolFamily('fido2');
                    break;
                }
            }
        } else {
            metadataV3.setProtocolFamily(metadataV2.getProtocolFamily()!)
        }

        metadataV3.setSchema(3);

        if(metadataV2.getUpv() !== undefined) {
            metadataV3.setUpv(metadataV2.getUpv()!)
        }

        let auxAuthenticationAlgorithms: string[] = [];
        if(metadataV2.getAuthenticationAlgorithm() !== undefined) {
            auxAuthenticationAlgorithms.push(authAlgorithm[metadataV2.getAuthenticationAlgorithm()]);
        }
        if(metadataV2.getAuthenticationAlgorithms() !== undefined) {
            for(const ele in metadataV2.getAuthenticationAlgorithms()) {
                auxAuthenticationAlgorithms.push(authAlgorithm[ele]);
            }
        }
        metadataV3.setAuthenticationAlgorithms(auxAuthenticationAlgorithms);

        let auxPublicKeyAlgAndEncoding: string[] = [];
        if(metadataV2.getPublicKeyAlgAndEncoding() !== undefined) {
            auxPublicKeyAlgAndEncoding.push(PKAlgAndEncodings[metadataV2.getPublicKeyAlgAndEncoding()]);
        }
        if(metadataV2.getPublicKeyAlgAndEncodings() !== undefined) {
            for(const ele in metadataV2.getPublicKeyAlgAndEncodings()) {
                auxPublicKeyAlgAndEncoding.push(PKAlgAndEncodings[ele]);
            }
        }
        metadataV3.setPublicKeyAlgAndEncodings(auxPublicKeyAlgAndEncoding);

        if(metadataV2.getAttestationTypes() !== undefined) {
            let auxAttestationTypes: string[] = [];
            metadataV2.getAttestationTypes().forEach(element => {
                auxAttestationTypes.push(attestations[element]);
            });
            metadataV3.setAttestationTypes(auxAttestationTypes);
        }

        //userVerification

        if(metadataV2.getKeyProtection() !== undefined) {
            let val = metadataV2.getKeyProtection();
            let auxKeyProtection: string[] = [];
            const keys = Object.values(KProtection);

            const arrayKeys: number[] = [];
            keys.forEach((value) => {
                if(!(isNaN(Number(value)))) {
                    arrayKeys.push(Number(value));
                }
            });
            
            while(val != 0) {
                for(let i = 0; i<arrayKeys.length; i++) {
                    if(arrayKeys[i]>val) {
                        val = val - arrayKeys[i-1];
                        auxKeyProtection.push(KProtection[arrayKeys[i-1]]);
                        break;
                    }else if(arrayKeys[i] == val) {
                        val = val - arrayKeys[i];
                        auxKeyProtection.push(KProtection[arrayKeys[i]]);
                        break;
                    } else if(i == arrayKeys.length-1) {
                        if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                            val = val - arrayKeys[i];
                            auxKeyProtection.push(KProtection[arrayKeys[i]]);
                            break;
                        }
                    }
                }
            }

            metadataV3.setKeyProtection(auxKeyProtection);
        }

        if(metadataV2.getIsKeyRestricted() !== undefined) {
            metadataV3.setIsKeyRestricted(metadataV2.getIsKeyRestricted()!);
        }

        if(metadataV2.getIsFreshUserVerificationRequired() !== undefined) {
            metadataV3.setIsFreshUserVerificationRequired(metadataV2.getIsFreshUserVerificationRequired()!);
        }

        if(metadataV2.getMatcherProtection() !== undefined) {
            let val = metadataV2.getMatcherProtection();
            let auxMatcherProtection: string[] = [];
            const keys = Object.values(matcher);

            const arrayKeys: number[] = [];
            keys.forEach((value) => {
                if(!(isNaN(Number(value)))) {
                    arrayKeys.push(Number(value));
                }
            });
            
            while(val != 0) {
                for(let i = 0; i<arrayKeys.length; i++) {
                    if(arrayKeys[i]>val) {
                        val = val - arrayKeys[i-1];
                        auxMatcherProtection.push(matcher[arrayKeys[i-1]]);
                        break;
                    }else if(arrayKeys[i] == val) {
                        val = val - arrayKeys[i];
                        auxMatcherProtection.push(matcher[arrayKeys[i]]);
                        break;
                    } else if(i == arrayKeys.length-1) {
                        if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                            val = val - arrayKeys[i];
                            auxMatcherProtection.push(matcher[arrayKeys[i]]);
                            break;
                        }
                    }
                }
            }

            metadataV3.setMatcherProtection(auxMatcherProtection);
        }

        if(metadataV2.getCryptoStrength() !== undefined) {
            metadataV3.setCryptoStrength(metadataV2.getCryptoStrength()!);
        }

        if(metadataV2.getAttachmentHint() !== undefined) {
            let val = metadataV2.getAttachmentHint();
            let auxAttachmentHint: string[] = [];
            const keys = Object.values(attachmentHintValues);

            const arrayKeys: number[] = [];
            keys.forEach((value) => {
                if(!(isNaN(Number(value)))) {
                    arrayKeys.push(Number(value));
                }
            });
            
            while(val != 0) {
                for(let i = 0; i<arrayKeys.length; i++) {
                    if(arrayKeys[i]>val) {
                        val = val - arrayKeys[i-1];
                        auxAttachmentHint.push(attachmentHintValues[arrayKeys[i-1]]);
                        break;
                    }else if(arrayKeys[i] == val) {
                        val = val - arrayKeys[i];
                        auxAttachmentHint.push(attachmentHintValues[arrayKeys[i]]);
                        break;
                    } else if(i == arrayKeys.length-1) {
                        if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                            val = val - arrayKeys[i];
                            auxAttachmentHint.push(attachmentHintValues[arrayKeys[i]]);
                            break;
                        }
                    }
                }
            }

            metadataV3.setAttachmentHint(auxAttachmentHint);
        }

        if(metadataV2.getTcDisplay() !== undefined) {
            let val = metadataV2.getTcDisplay();
            let auxTcDisplay: string[] = [];
            const keys = Object.values(tcDisplayValues);

            const arrayKeys: number[] = [];
            keys.forEach((value) => {
                if(!(isNaN(Number(value)))) {
                    arrayKeys.push(Number(value));
                }
            });
            
            while(val != 0) {
                for(let i = 0; i<arrayKeys.length; i++) {
                    if(arrayKeys[i]>val) {
                        val = val - arrayKeys[i-1];
                        auxTcDisplay.push(tcDisplayValues[arrayKeys[i-1]]);
                        break;
                    }else if(arrayKeys[i] == val) {
                        val = val - arrayKeys[i];
                        auxTcDisplay.push(tcDisplayValues[arrayKeys[i]]);
                        break;
                    } else if(i == arrayKeys.length-1) {
                        if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                            val = val - arrayKeys[i];
                            auxTcDisplay.push(tcDisplayValues[arrayKeys[i]]);
                            break;
                        }
                    }
                }
            }

            metadataV3.setAttachmentHint(auxTcDisplay);
        }

        if(metadataV2.getTcDisplayContentType() !== undefined) {
            metadataV3.setTcDisplayContentType(metadataV2.getTcDisplayContentType()!);
        }

        if(metadataV2.getTcDisplayPNGCharacteristics() !== undefined) {
            metadataV3.setTcDisplayPNGCharacteristics(metadataV2.getTcDisplayPNGCharacteristics()!);
        }

        if(metadataV2.getAttestationRootCertificates() !== undefined) {
            metadataV3.setAttestationRootCertificates(metadataV2.getAttestationRootCertificates());
        }

        if(metadataV2.getEcdaaTrustAnchors() !== undefined) {
            metadataV3.setEcdaaTrustAnchors(metadataV2.getEcdaaTrustAnchors()!);
        }

        if(metadataV2.getIcon() !== undefined) {
            metadataV3.setIcon(metadataV2.getIcon()!);
        }

        if(metadataV2.getSupportedExtensions() !== undefined) {
            metadataV3.setSupportedExtensions(metadataV2.getSupportedExtensions()!);
        }

        if(metadataV2.getAssertionScheme() == 'FIDOV2') {
            let aaguid:string = '';
            let versions: string[] = [];
            let auxAuthenticatorInfo: AuthenticatorGetInfo = {aaguid,versions};
            auxAuthenticatorInfo.aaguid = metadataV2.getAAGUID()!;
            // authenticatorInfo.versions = 
            metadataV3.setAuthenticatorGetInfo(auxAuthenticatorInfo);
        }

        return metadataV3;
    }

    private legalHeader?: string;
    public getLegalHeader() {
        return this.legalHeader;
    }
    public setLegalHeader(legalHeader: string) {
        this.legalHeader = legalHeader;
    }
    public validateLegalHeader(): boolean {
        if (!this.legalHeader) { return true; }
        try {
          new URL(this.legalHeader);
          return true;
        } catch (error) {
          return false;
        }
    }   

    private aaid?: AAID;
    public getAAID(): string | undefined {
        return this.aaid;
    }
    public setAAID(aaid: string) {
        this.aaid = aaid;
    }
    public validateAAID(): boolean {
        if(this.getProtocolFamily() === 'uaf' && !this.getAAGUID()) {
            if(this.aaid) {
                const aaidPattern = /\d{4}[#]\d{4}/;
                return aaidPattern.test(this.aaid);
            }
            return false;
        }
        if(this.aaid) {
            return false;
        } else {
            return true;
        }
    }

    private aaguid?: AAGUID;
    public getAAGUID(): string | undefined {
        return this.aaguid;
    }
    public setAAGUID(aaguid: string) {
        this.aaguid = aaguid;
    }
    public validateAAGUID(): boolean {
        if(this.getProtocolFamily() === 'fido2' && !this.getAAID()) {
            if(this.aaguid) {
                // Regular expression to match UUID (8-4-4-4-12 format)
                const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
                return uuidPattern.test(this.aaguid);
            }
            return false;
        }
        if(this.aaguid) {
            return false;
        } else {
            return true;
        }
    }
      

    private attestationCertificateKeyIdentifiers?: string[];
    public getAttestationCertificateKeyIdentifiers(): string[] | undefined {
        return this.attestationCertificateKeyIdentifiers;
    }
    public setAttestationCertificateKeyIdentifiers(attestationCertificateKeyIdentifiers: string[]) {
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
    }
    public validateAttestationCertificateKeyIdentifiers(): boolean {
        if(!this.getAAID() && !this.getAAGUID()) {
            if(this.attestationCertificateKeyIdentifiers) {
                const hexPattern = /^[0-9a-f]+$/;
                for (const identifier of this.attestationCertificateKeyIdentifiers) {
                    if (!hexPattern.test(identifier)) {
                    return false;
                    }
                }
                return true;
            }
            return false;
        }
        if(this.attestationCertificateKeyIdentifiers) {
            return false;
        } else {
            return true;
        }
    }

    private description: string;
    public getDescription(): string {
        return this.description;
    }
    public setDescription(description: string) {
        this.description = description;
    }
    public validateDescription(): boolean {
        return !!this.description;
    }

    private alternativeDescriptions?: alternativeDescriptionsType;
    public getAlternativeDescriptions() : alternativeDescriptionsType | undefined {
        return this.alternativeDescriptions;
    }
    public setAlternativeDescriptions(alternativeDescriptions: alternativeDescriptionsType) {
        this.alternativeDescriptions = alternativeDescriptions;
    }
    public validateAlternativeDescriptions(): boolean {
        if (!this.alternativeDescriptions) { return true; }
      
        // Check if all values in alternativeDescriptions are strings
        for (const languageCode in this.alternativeDescriptions) {
          if (!this.alternativeDescriptions.hasOwnProperty(languageCode)) {
            continue;
        }
      
        const description = this.alternativeDescriptions[languageCode];
        if (typeof description !== 'string') {
            return false;
        }
        }
        return true;
    }
      

    private authenticatorVersion: number;
    public getAuthenticatorVersion() : number {
        return this.authenticatorVersion;
    }
    public setAuthenticatorVersion(authenticatorVersion: number) {
        this.authenticatorVersion = authenticatorVersion;
    }
    public validateAuthenticatorVersion(): boolean {
      
        // Check if authenticatorVersion is a positive whole number within the range of an unsigned 16-bit integer
        return Number.isInteger(this.authenticatorVersion) && this.authenticatorVersion >= 0 && this.authenticatorVersion <= 65535;
    }  

    private protocolFamily: string;
    public getProtocolFamily(): string | undefined {
        return this.protocolFamily;
    }
    public setProtocolFamily(protocolFamily: string) {
        this.protocolFamily = protocolFamily;
    }
    public validateProtocolFamily(): boolean {
        if (this.protocolFamily == '') { return false; }
        
        const validValues = ['uaf', 'u2f', 'fido2'];
        
        return validValues.includes(this.protocolFamily);
    }

    private schema: number;
    public getSchema(): number {
        return this.schema;
    }
    public setSchema(schema: number) {
        this.schema = schema;
    }
    public validateSchema(): boolean {
        if(this.schema === undefined) { return false; }
        return this.schema == 3 ? true : false;
    }

    //campo dati marcato come readonly, non ha quindi senso mettere un setter
    private upv: upvType[];
    public getUpv(): upvType[] {
        return this.upv;
    }
    private setUpv(upv: upvType[]) {
        this.upv = upv;
    }
    public validateUpv(): boolean {
        if (!Array.isArray(this.upv) || this.upv.length === 0) {
            return false;
        }

        for (const version of this.upv) {
            if (!(Number.isInteger(this.authenticatorVersion) && this.authenticatorVersion >= 0 && this.authenticatorVersion <= 65535)) {
              return false;
            }
        }
        return true;
    }

    private authenticationAlgorithms: string[];
    public getAuthenticationAlgorithms(): string[] {
        return this.authenticationAlgorithms;
    }
    public setAuthenticationAlgorithms(authenticationAlgorithms: string[]) {
        this.authenticationAlgorithms = authenticationAlgorithms;
    }
    public validateAuthenticationAlgorithms(): boolean {
        if(this.authenticationAlgorithms.length == 0) { return false; }

        for (const algorithm of this.authenticationAlgorithms) {
            if(!(algorithm in authAlgorithm)) {
                return false;
            }
        }
        return true;
    }

    private publicKeyAlgAndEncodings: string[];
    public getPublicKeyAlgAndEncodings(): string[] {
        return this.publicKeyAlgAndEncodings;
    }
    public setPublicKeyAlgAndEncodings(publicKeyAlgAndEncodings: string[]) {
        this.publicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
    }
    public validatePublicKeyAlgAndEncodings(): boolean {
        if(this.publicKeyAlgAndEncodings.length == 0) { return false; }

        for (const encoding of this.publicKeyAlgAndEncodings) {
            if (!(encoding in PKAlgAndEncodings)) {
                return false;
            }
        }
        return true;
    }

    private attestationTypes: string[];
    public getAttestationTypes(): string[] {
        return this.attestationTypes;
    }
    public setAttestationTypes(attestationTypes: string[]) {
        this.attestationTypes = attestationTypes;
    }
    public validateAttestationTypes(): boolean {
        if(this.attestationTypes.length == 0) { return false; }

        this.attestationTypes.forEach((value) => {
            if(!(value in attestations)) {
                return false;
            }
        })
        return true;
    }

    // userVerificationDetails
    private userVerificationDetails:  userVerificationDetailsType[][];
    public getUserVerificationDetails(): userVerificationDetailsType[][] {
        return this.userVerificationDetails;
    }
    public setUserVerificationDetails(userVerificationDetails: userVerificationDetailsType[][]) {
        this.userVerificationDetails = userVerificationDetails;
    }
    public validateUserVerificationDetails(): boolean {
        if(!this.userVerificationDetails) { return false; }
        
        this.userVerificationDetails.forEach((value) => {
            if(!(value[0].userVerificationMethod in userVerificationValues)) {
                return false;
            }
        })

        return true;
    }

    private keyProtection: string[];
    public getKeyProtection(): string[] {
        return this.keyProtection;
    }
    public setKeyProtection(keyProtection: string[]) {
        this.keyProtection = keyProtection;
    }
    public validateKeyProtection(): boolean {
        if(this.keyProtection.length == 0 || this.keyProtection === undefined) { return false; }
    
        this.keyProtection.forEach((value) => {
            if(!(value in KProtection)) {
                return false;
            }
        })
        return true;
    } 

    private isKeyRestricted?: boolean;
    public getIsKeyRestricted(): boolean | undefined {
        return this.isKeyRestricted;
    }
    public setIsKeyRestricted(isKeyRestricted: boolean) {
        this.isKeyRestricted = isKeyRestricted;
    }
    public validateIsKeyRestricted(): boolean {
        if(this.isKeyRestricted === undefined) { return true; }
        return typeof this.isKeyRestricted === 'boolean';
    }

    private isFreshUserVerificationRequired?: boolean;
    public getIsFreshUserVerificationRequired(): boolean | undefined {
        return this.isFreshUserVerificationRequired;
    } 
    public setIsFreshUserVerificationRequired(isFreshUserVerificationRequired: boolean) {
        this.isFreshUserVerificationRequired = isFreshUserVerificationRequired;
    }
    public validateIsFreshUserVerificationRequired(): boolean {
        return this.isFreshUserVerificationRequired === undefined || typeof this.isFreshUserVerificationRequired === 'boolean';
    }

    private matcherProtection: string[];
    public getMatcherProtection(): string[] {
        return this.matcherProtection;
    }
    public setMatcherProtection(matcherProtection: string[]) {
        this.matcherProtection = matcherProtection
    }
    public validateMatcherProtection(): boolean {
        if(this.matcherProtection.length == 0 || this.matcherProtection === undefined) { return false; }
    
        this.matcherProtection.forEach((value) => {
            if(!(value in matcher)) {
                return false;
            }
        })
        return true;
    }

    private cryptoStrength?: number;
    public getCryptoStrength(): number | undefined {
        return this.cryptoStrength;
    }
    public setCryptoStrength(cryptoStrength: number) {
        this.cryptoStrength = cryptoStrength;
    }
    //controlla meglio
    public validateCryptoStrength(): boolean {
        if(!this.cryptoStrength) { return true; }
        return Number.isInteger(this.cryptoStrength) && this.cryptoStrength > 0;
    }

    //capire se è required o no
    //controllare MDS2
    private attachmentHint: string[];
    public getAttachmentHint(): string[] {
        return this.attachmentHint;
    }
    public setAttachmentHint(attachmentHint: string[]) {
        this.attachmentHint = attachmentHint;
    }
    public validateAttachmentHint(): boolean {
        if(this.attachmentHint.length == 0) {return false;}

        this.attachmentHint.forEach((value) => {
            if(!(value in attachmentHintValues)) {
                return false;
            }
        })
        return true;
    }

    private tcDisplay: string[];
    public getTcDisplay(): string[] {
        return this.tcDisplay;
    }
    public setTcDisplay(tcDisplay: string[]) {
        this.tcDisplay = tcDisplay;
    }
    public validateTcDisplay(): boolean {
        if(this.tcDisplay === undefined) { return false; }
    
        this.tcDisplay.forEach((value) => {
            if(!(value in tcDisplayValues)) {
                return false;
            }
        })
        return true;
    }

    private tcDisplayContentType?: string;
    public getTcDisplayContentType(): string | undefined {
        return this.tcDisplayContentType;
    }
    public setTcDisplayContentType(tcDisplayContentType: string) {
        this.tcDisplayContentType = tcDisplayContentType;
    }
    public validateTcDisplayContentType(): boolean {
        let status: Boolean = true;

        if(this.getTcDisplay().length == 0) {
            status = false;
        } else {
            this.getTcDisplay().forEach((value) => {
                if(value == '') {
                    status = false;
                }
            });
        }

        const allowedContentTypes = ['image/png', 'text/plain'];

        if(status && this.tcDisplayContentType !== undefined && this.tcDisplayContentType != '') {
            return allowedContentTypes.includes(this.tcDisplayContentType);
        } else if(!status && (this.tcDisplayContentType === undefined || this.tcDisplayContentType == '')){
            return true;
        }
        return false;
    }

    private tcDisplayPNGCharacteristics?: tcDisplayPNGCharacteristicsType[];
    public getTcDisplayPNGCharacteristics(): tcDisplayPNGCharacteristicsType[] | undefined {
        return this.tcDisplayPNGCharacteristics;
    }
    public setTcDisplayPNGCharacteristics(tcDisplayPNGCharacteristics: tcDisplayPNGCharacteristicsType[]) {
        this.tcDisplayPNGCharacteristics = tcDisplayPNGCharacteristics;
    }
    public validateTcDisplayPNGCharacteristics(): boolean {
        let status: Boolean = true;

        if(this.getTcDisplay().length == 0) {
            status = false;
        } else {
            this.getTcDisplay().forEach((value) => {
                if(value == '') {
                    status = false;
                }
            });
        }
        if(status && this.getTcDisplayContentType() != 'image/png') {
            status = false;
        }

        if(status && this.tcDisplayPNGCharacteristics !== undefined && this.tcDisplayPNGCharacteristics.length != 0) {
            
            const isValidEntry = (entry: tcDisplayPNGCharacteristicsType) => {
                return (
                    typeof entry.width === 'number' &&
                    typeof entry.height === 'number' &&
                    typeof entry.bitDepth === 'number' &&
                    typeof entry.colorType === 'number' &&
                    typeof entry.compression === 'number' &&
                    typeof entry.filter === 'number' &&
                    typeof entry.interlace === 'number' &&
                    (entry.plte === undefined || (Array.isArray(entry.plte) && entry.plte.length))
                );
            };    
            return this.tcDisplayPNGCharacteristics.every(isValidEntry);
        } else if(!status && (this.tcDisplayPNGCharacteristics === undefined || this.tcDisplayPNGCharacteristics.length == 0)) {
                return true;
            }
        return false;
    }

    private attestationRootCertificates: string[];
    public getAttestationRootCertificates(): string[] {
        return this.attestationRootCertificates;
    }
    public setAttestationRootCertificates(attestationRootCertificates: string[]) {
        this.attestationRootCertificates = attestationRootCertificates;
    }
    public validateAttestationRootCertificates(): boolean {
        if(this.attestationRootCertificates.length == 0 || this.attestationRootCertificates === undefined) {
            return false;
        } 

        const { X509Certificate } = require('node:crypto');
        
        for (const certificate of this.attestationRootCertificates) {
            if (typeof certificate !== 'string') {
              return false;
            }
      
            try {
              const certBuffer = Buffer.from(certificate, 'base64');
              const x509Cert = new X509Certificate(certBuffer);
            } catch (error) {
              return false;
            }
        }
        return true;
    }
      
    private ecdaaTrustAnchors?: ecdaaTrustAnchorsType[];
    public getEcdaaTrustAnchors(): ecdaaTrustAnchorsType[] | undefined {
        return this.ecdaaTrustAnchors;
    }
    public setEcdaaTrustAnchors(ecdaaTrustAnchors: ecdaaTrustAnchorsType[]) {
        this.ecdaaTrustAnchors = ecdaaTrustAnchors;
    }
    public validateEcdaaTrustAnchors(): boolean {
        const ecdaa = 15581
        if(this.getAttestationTypes().includes(attestations[ecdaa])) {
            if(this.ecdaaTrustAnchors === undefined) { return false; }
            else {
                if (!this.ecdaaTrustAnchors.every(this.isValidEcdaaTrustAnchor)) {
                    return false;
                }
            }
        }
        return true;
    } 
    public isValidEcdaaTrustAnchor(trustAnchor: ecdaaTrustAnchorsType): boolean {
        if (
          typeof trustAnchor.X !== 'string' ||
          typeof trustAnchor.Y !== 'string' ||
          typeof trustAnchor.c !== 'string' ||
          typeof trustAnchor.sx !== 'string' ||
          typeof trustAnchor.sy !== 'string' ||
          typeof trustAnchor.G1Curve !== 'string'
        ) {
          return false;
        }
      
        return true;
    }

    private icon?: string;
    public getIcon(): string | undefined {
        return this.icon;
    }
    public setIcon(icon: string) {
        this.icon = icon;
    }
    public validateIcon(): boolean {
        // The icon should be a non-empty string
        if (!this.icon || this.icon.trim() === '') {
            return true;
        }
        // Regular expression to match a data URL-encoded PNG image
        const dataUrlRegex = /^data:image\/png;base64,([A-Za-z0-9+/=]+)/;

        const match = this.icon.match(dataUrlRegex);

        return !!match; // If match is truthy, the icon is a valid data URL-encoded PNG image
    }

    private supportedExtensions?: supportedExtensionsType[];
    public getSupportedExtensions(): supportedExtensionsType[] | undefined {
        return this.supportedExtensions;
    }
    public setSupportedExtensions(supportedExtensions: supportedExtensionsType[]) {
        this.supportedExtensions = supportedExtensions;
    }
    public validateSupportedExtensions(): boolean {
        if(this.supportedExtensions !== undefined) {
            for(const extension of this.supportedExtensions) {
                if(!extension.id || extension.fail_if_unknown === undefined) {
                    return false;
                }
            }
            return true;
        }
        return true;
    }

    private authenticatorGetInfo?: AuthenticatorGetInfo;
    public getAuthenticatorGetInfo(): AuthenticatorGetInfo | undefined {
        return this.authenticatorGetInfo;
    }
    public setAuthenticatorGetInfo(authenticatorGetInfo: AuthenticatorGetInfo) {
        this.authenticatorGetInfo = authenticatorGetInfo;
    }
    public validateAuthenticatorGetInfo(): boolean {
        if(this.authenticatorGetInfo === undefined) {
            if((this.getProtocolFamily() == 'uaf' || this.getProtocolFamily() == 'u2f')) {
                return true;
            }
        } else {
            if(this.authenticatorGetInfo.versions === undefined || this.authenticatorGetInfo.versions.length == 0) {
                return false;
            }
            const versionsValues = ['U2F_V2', 'FIDO_2_0'];

            this.authenticatorGetInfo.versions.forEach((value) => {
                if(!(versionsValues.includes(value))) {
                    return false;
                }
            })

            if(this.authenticatorGetInfo.aaguid === undefined || this.authenticatorGetInfo.aaguid == '') {
                return false;
            }

            if(!(/^[0-9a-f]{32}$/i.test(this.authenticatorGetInfo.aaguid))) {
                return false;
            }
        }
        //se non vogliamo eseguire altri test, possiamo direttamente fare il return del risultato del test con la RegEx
        return true;
    }


}

export { MetadataV3 };
