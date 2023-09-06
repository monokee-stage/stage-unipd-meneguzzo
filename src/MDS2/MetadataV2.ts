import { MetadataV3 } from "../MDS3/MetadataV3";


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
    userVerification: number;
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

class MetadataV2 {
    private constructor() {}

    public static initialize<T extends MetadataV2>(data: T): MetadataV2 {
        const result = new MetadataV2();
        const dataJson = JSON.stringify(data);
        Object.assign(result, JSON.parse(dataJson));
        return result;
    }

    // public static initialize<T extends MetadataV2>(data: T) : MetadataV2 {
    //     let result = new MetadataV2();
    //     // let property: keyof typeof data;
    //     for(const property in data) {
    //         if(data.hasOwnProperty(property)) {
    //             // result[property] = data[property];
    //             if (property === "legalHeader") {
    //                 result.setLegalHeader(data[property] as string);
    //             }
    //         }
            
            
    //     }
    //     return result;
    // }

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
        if(this.getAssertionScheme() === 'UAFV1TLV' && !this.getAAGUID()) {
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
        if(this.getAssertionScheme() === 'FIDOV2' && !this.getAAID()) {
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

    private protocolFamily?: string = 'uaf';
    public getProtocolFamily(): string | undefined {
        return this.protocolFamily;
    }
    public setProtocolFamily(protocolFamily: string) {
        if(protocolFamily != '') {
            this.protocolFamily = protocolFamily;
        }
    }
    public validateProtocolFamily(): boolean {
        if (!this.protocolFamily) { return true; }
        
        const validValues = ['uaf', 'u2f', 'fido2'];
        
        return validValues.includes(this.protocolFamily);
    }

    //campo dati marcato come readonly, non ha quindi senso mettere un setter
    private upv: upvType[];
    public getUpv(): upvType[] {
        return this.upv;
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

    private assertionScheme: string;
    public getAssertionScheme(): string {
        return this.assertionScheme;
    }
    public setAssertionScheme(assertionScheme: string) {
        this.assertionScheme = assertionScheme;
    }
    public validateAssertionScheme(): boolean {   
        const validValues = ['UAFV1TLV', 'U2FV1BIN', 'FIDOV2'];
        
        return validValues.includes(this.assertionScheme);
    }

    private authenticationAlgorithm: number;
    public getAuthenticationAlgorithm(): number {
        return this.authenticationAlgorithm;
    }
    public setAuthenticationAlgorithm(authenticationAlgorithm: number) {
        this.authenticationAlgorithm = authenticationAlgorithm;
    }
    public validateAuthenticationAlgorithm(): boolean {
        return this.authenticationAlgorithm in authAlgorithm;
    }

    private authenticationAlgorithms?: number[];
    public getAuthenticationAlgorithms(): number[] | undefined {
        return this.authenticationAlgorithms;
    }
    public setAuthenticationAlgorithms(authenticationAlgorithms: number[]) {
        this.authenticationAlgorithms = authenticationAlgorithms;
    }
    public validateAuthenticationAlgorithms(): boolean {
        if(this.authenticationAlgorithms === undefined) { return true; }
        
        for (const algorithm of this.authenticationAlgorithms) {
            if (!(algorithm in authAlgorithm)) {
                return false;
            }
        }
        return true;
    }

    private publicKeyAlgAndEncoding: number;
    public getPublicKeyAlgAndEncoding(): number {
        return this.publicKeyAlgAndEncoding;
    }
    public setPublicKeyAlgAndEncoding(publicKeyAlgAndEncoding: number) {
        this.publicKeyAlgAndEncoding = publicKeyAlgAndEncoding;
    }
    public validatePublicKeyAlgAndEncoding():  boolean {
        return this.publicKeyAlgAndEncoding in PKAlgAndEncodings;
    }

    private publicKeyAlgAndEncodings?: number[];
    public getPublicKeyAlgAndEncodings(): number[] | undefined {
        return this.publicKeyAlgAndEncodings;
    }
    public setPublicKeyAlgAndEncodings(publicKeyAlgAndEncodings: number[]) {
        this.publicKeyAlgAndEncodings = publicKeyAlgAndEncodings;
    }
    public validatePublicKeyAlgAndEncodings(): boolean {
        if(this.publicKeyAlgAndEncodings === undefined) { return true; }

        for (const encoding of this.publicKeyAlgAndEncodings) {
            if (!(encoding in PKAlgAndEncodings)) {
                return false;
            }
        }
        return true;
    }

    private attestationTypes: number[];
    public getAttestationTypes(): number [] {
        return this.attestationTypes;
    }
    public setAttestationTypes(attestationTypes: number[]) {
        this.attestationTypes = attestationTypes;
    }
    public validateAttestationTypes(): boolean {
        if(this.attestationTypes.length == 0) { return false; }

        const attestationType = Object.values(this.attestationTypes);

        attestationType.forEach((value) => {
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
        
        for(const value of this.userVerificationDetails) {
            if(!(value[0].userVerification in userVerificationValues)) {
                return false;
            }
        }
        return true;
    }

    private keyProtection: number;
    public getKeyProtection(): number {
        return this.keyProtection;
    }
    public setKeyProtection(keyProtection: number) {
        this.keyProtection = keyProtection;
    }
    public validateKeyProtection(): boolean {
        let val = this.keyProtection;
        const keys = Object.values(KProtection);

        const arrayKeys: number[] = [];
        keys.forEach((value) => {
            if(!(isNaN(Number(value)))) {
                arrayKeys.push(Number(value));
            }
        })
        
        while(val != 0) {
            for(let i = 0; i<arrayKeys.length; i++) {
                if(arrayKeys[i]>val) {
                    val = val - arrayKeys[i-1];
                    break;
                }else if(arrayKeys[i] == val) {
                    val = val - arrayKeys[i];
                    break;
                } else if(i == arrayKeys.length-1) {
                    if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                        val = val - arrayKeys[i];
                        break;
                    } else {
                        return false;
                    }
                }
            }
        }
        if(val == 0) {
            return true;
        }
        return false;
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
        return typeof this.isFreshUserVerificationRequired === 'undefined' || typeof this.isFreshUserVerificationRequired === 'boolean';
    }

    private matcherProtection: number;
    public getMatcherProtection(): number {
        return this.matcherProtection;
    }
    public setMatcherProtection(matcherProtection: number) {
        this.matcherProtection = matcherProtection
    }
    public validateMatcherProtection(): boolean {
        let val = this.matcherProtection;
        const keys = Object.values(matcher);

        const arrayKeys: number[] = [];
        keys.forEach((value) => {
            if(!(isNaN(Number(value)))) {
                arrayKeys.push(Number(value));
            }
        })
        
        while(val != 0) {
            for(let i = 0; i<arrayKeys.length; i++) {
                if(arrayKeys[i]>val) {
                    val = val - arrayKeys[i-1];
                    break;
                }else if(arrayKeys[i] == val) {
                    val = val - arrayKeys[i];
                    break;
                } else if(i == arrayKeys.length-1) {
                    if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                        val = val - arrayKeys[i];
                        break;
                    } else {
                        return false;
                    }
                }
            }
        }
        if(val == 0) {
            return true;
        }
        return false;
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

    private operatingEnv?: string;
    public getOperatingEnv(): string | undefined {
        return this.operatingEnv;
    }
    public setOperatingEnv(operatingEnv: string) {
        this.operatingEnv = operatingEnv;
    }
    public validateOperatingEnv(): boolean{
        if(!this.operatingEnv) { return true; }
        const validOperatingEnv = [
            'TEEs based on ARM TrustZone HW',
            'TEE Based on Intel VT HW',
            'TEE Based on Intel SGX HW',
            'TEE Based on Intel ME/TXE HW',
            'TEE with GlobalPlatform TEE Protection Profile Certification',
            'Windows 10 Virtualization-based Security.',
            'Secure World of AMD PSP (Platform Security coProcessor).',
            'Trusted Platform Modules (TPMs) Complying to Trusted Computing Group specifications.',
            'Secure Element (SE)'
        ]

        return validOperatingEnv.includes(this.operatingEnv);
    }

    private attachmentHint: number;
    public getAttachmentHint(): number {
        return this.attachmentHint;
    }
    public setAttachmentHint(attachmentHint: number) {
        this.attachmentHint = attachmentHint;
    }
    public validateAttachmentHint(): boolean {
        let val = this.attachmentHint;
        const keys = Object.values(attachmentHintValues);

        const arrayKeys: number[] = [];
        keys.forEach((value) => {
            if(!(isNaN(Number(value)))) {
                arrayKeys.push(Number(value));
            }
        })
        
        while(val != 0) {
            for(let i = 0; i<arrayKeys.length; i++) {
                if(arrayKeys[i]>val) {
                    val = val - arrayKeys[i-1];
                    break;
                }else if(arrayKeys[i] == val) {
                    val = val - arrayKeys[i];
                    break;
                } else if(i == arrayKeys.length-1) {
                    if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                        val = val - arrayKeys[i];
                        break;
                    } else {
                        return false;
                    }
                }
            }
        }
        if(val == 0) {
            return true;
        }
        return false;
    }

    //controllare se si può inizializzare meglio
    private isSecondFactorOnly: boolean;
    public getIsSecondFactorOnly(): boolean {
        return this.isSecondFactorOnly;
    }
    public setIsSecondFactorOnly(isSecondFactorOnly: boolean) {
        this.isSecondFactorOnly = isSecondFactorOnly;
    }
    public validateIsSecondFactorOnly(): boolean {
        return typeof this.isSecondFactorOnly === 'boolean';
    }

    private tcDisplay: number;
    public getTcDisplay(): number {
        return this.tcDisplay;
    }
    public setTcDisplay(tcDisplay: number) {
        this.tcDisplay = tcDisplay;
    }
    public validateTcDisplay(): boolean {
        let val = this.tcDisplay;
        const keys = Object.values(tcDisplayValues);

        const arrayKeys: number[] = [];
        keys.forEach((value) => {
            if(!(isNaN(Number(value)))) {
                arrayKeys.push(Number(value));
            }
        })
        
        while(val != 0) {
            for(let i = 0; i<arrayKeys.length; i++) {
                if(arrayKeys[i]>val) {
                    val = val - arrayKeys[i-1];
                    break;
                }else if(arrayKeys[i] == val) {
                    val = val - arrayKeys[i];
                    break;
                } else if(i == arrayKeys.length-1) {
                    if(val > arrayKeys[i] && val < 2*(arrayKeys[i])) {
                        val = val - arrayKeys[i];
                        break;
                    } else {
                        return false;
                    }
                }
            }
        }
        if(val == 0) {
            return true;
        }
        return false;
    }

    private tcDisplayContentType?: string;
    public getTcDisplayContentType(): string | undefined {
        return this.tcDisplayContentType;
    }
    public setTcDisplayContentType(tcDisplayContentType: string) {
        this.tcDisplayContentType = tcDisplayContentType;
    }
    public validateTcDisplayContentType(): boolean {
        if(!this.tcDisplayContentType && this.getTcDisplay() == 0) { return true; }
        
        if(this.tcDisplayContentType) {
            const allowedContentTypes = ['image/png', 'text/plain'];

            return allowedContentTypes.includes(this.tcDisplayContentType);
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
        if(this.getTcDisplay() != 0 && this.getTcDisplayContentType() == 'image/png') {
            if(this.tcDisplayPNGCharacteristics == undefined) {
                return false; 
            } else {
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
            }

        } else if(this.tcDisplayPNGCharacteristics == undefined) {
            return true;
        } else {
            return false;
        }
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
        if(this.getAttestationTypes().includes(attestations.ecdaa)) {
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
                if(!extension.id || !extension.fail_if_unknown) {
                    return false;
                }
            }
            return true;
        }
        return true;
    }
}

export { MetadataV2 };
