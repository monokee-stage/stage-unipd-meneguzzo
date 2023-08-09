import {MetadataV3} from './MetadataV3'

export function validateMetadataV3(metadata: MetadataV3) {
    
  const validationErrors: string[] = [];
  // Perform your validation checks here
  // Return true if valid, false if invalid
  if (!metadata.validateLegalHeader()) {
    validationErrors.push('Legal header is invalid');
  }

  if (!metadata.validateAAID()) {
    validationErrors.push('AAID is invalid');
  }

  if (!metadata.validateAAGUID()) {
    validationErrors.push('AAGUID is invalid');
  }

  if(!metadata.validateAttestationCertificateKeyIdentifiers()) {
    validationErrors.push('attestationCertificateKeyIdentifiers is invalid');
  }

  if (!metadata.validateDescription()) {
    validationErrors.push('Description is invalid');
  }

  if(!metadata.validateAlternativeDescriptions()) {
    validationErrors.push('alternativeDescriptions is invalid');
  }

  if(!metadata.validateAuthenticatorVersion()) {
    validationErrors.push('authenticatorVersion is invalid');
  }

  if(!metadata.validateProtocolFamily()) {
    validationErrors.push('protocolFamily is invalid');
  }

  if(!metadata.validateUpv()) {
    validationErrors.push('upv is invalid');
  }

//   if(!metadata.validateAssertionScheme()) {
//     validationErrors.push('assertionScheme is invalid');
//   }

//   if(!metadata.validateAuthenticationAlgorithm()) {
//     validationErrors.push('authenticationAlgorithm is invalid');
//   }

  if(!metadata.validateAuthenticationAlgorithms()) {
    validationErrors.push('authenticationAlgorithms is invalid');
  }

//   if(!metadata.validatePublicKeyAlgAndEncoding()) {
//     validationErrors.push('publicKeyAlgAndEncoding is invalid');
//   }

  if(!metadata.validatePublicKeyAlgAndEncodings()) {
    validationErrors.push('publicKeyAlgAndEncodings is invalid');
  }

  if(!metadata.validateAttestationTypes()) {
    validationErrors.push('attestationTypes is invalid');
  }

  if(!metadata.validateUserVerificationDetails()) {
    validationErrors.push('userVerificationDetails is invalid');
  }

  if(!metadata.validateKeyProtection()) {
    validationErrors.push('keyProtection is invalid');
  }
  
  if(!metadata.validateIsKeyRestricted()) {
    validationErrors.push('isKeyRestricted is invalid');
  }

  if(!metadata.validateIsFreshUserVerificationRequired()) {
    validationErrors.push('isFreshUserVerificationRequired is invalid');
  }
  
  if(!metadata.validateMatcherProtection()) {
    validationErrors.push('matcherProtection is invalid');
  }

  if(!metadata.validateCryptoStrength()) {
    validationErrors.push('cryptoStrength is invalid');
  }

  if(!metadata.validateOperatingEnv()) {
    validationErrors.push('operatingEnv is invalid');
  }

  if(!metadata.validateAttachmentHint()) {
    validationErrors.push('attachmentHint is invalid');
  }

  if(!metadata.validateIsSecondFactorOnly()) {
    validationErrors.push('isSecondFactorOnly is invalid');
  }

  if(!metadata.validateTcDisplay()) {
    validationErrors.push('tcDisplay is invalid');
  }

  if(!metadata.validateTcDisplayContentType()) {
    validationErrors.push('tcDisplayContentType is invalid');
  }

  if(!metadata.validateTcDisplayPNGCharacteristics()) {
    validationErrors.push('tcDisplayPNGCharacteristics is invalid');
  }

  if(!metadata.validateAttestationRootCertificates()) {
    validationErrors.push('attestationRootCertificates is invalid');
  }

  if(!metadata.validateEcdaaTrustAnchors()) {
    validationErrors.push('ecdaaTrustAnchors is invalid');
  }

  if(!metadata.validateIcon()) {
    validationErrors.push('icon is invalid');
  }

  if(!metadata.validateSupportedExtensions()) {
    validationErrors.push('supportedExtensions is invalid');
  }

  console.log('error messages validation MetadataV3:', validationErrors)
}

// Define other validation functions here
