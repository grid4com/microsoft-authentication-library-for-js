/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { CredentialEntity } from "./CredentialEntity";
import { CredentialType, AuthenticationScheme } from "../../utils/Constants";
import { TimeUtils } from "../../utils/TimeUtils";
import { StringUtils } from "../../utils/StringUtils";
import { ICrypto } from "../../crypto/ICrypto";
import { TokenClaims } from "../../account/TokenClaims";
import { AuthToken } from "../../account/AuthToken";
import { ClientAuthError } from "../../error/ClientAuthError";

/**
 * ACCESS_TOKEN Credential Type
 *
 * Key Example: uid.utid-login.microsoftonline.com-accesstoken-clientId-contoso.com-user.read
 */
export class AccessTokenEntity extends CredentialEntity {
    /** Full tenant or organizational identifier that the account belongs to */
    realm: string;
    /** Permissions that are included in the token, or for refresh tokens, the resource identifier. */
    target: string;
    /** Absolute device time when entry was created in the cache. */
    cachedAt: string;
    /** Token expiry time, calculated based on current UTC time in seconds. Represented as a string. */
    expiresOn: string;
    /** Additional extended expiry time until when token is valid in case of server-side outage. Represented as string in UTC seconds. */
    extendedExpiresOn?: string;
    refreshOn?: string;
    /** used for POP and SSH tokenTypes */
    keyId?: string;
    /** Type of the token issued. Usually "Bearer" */
    tokenType?: AuthenticationScheme;
    requestedClaims?: string;
    requestedClaimsHash?: string;

    /**
     * Create AccessTokenEntity
     * @param homeAccountId
     * @param environment
     * @param accessToken
     * @param clientId
     * @param tenantId
     * @param scopes
     * @param expiresOn
     * @param extExpiresOn
     */
    static createAccessTokenEntity(
        homeAccountId: string,
        environment: string,
        accessToken: string,
        clientId: string,
        tenantId: string,
        scopes: string,
        expiresOn: number,
        extExpiresOn: number,
        cryptoUtils: ICrypto,
        refreshOn?: number,
        tokenType?: AuthenticationScheme,
        userAssertionHash?: string,
        keyId?: string,
        requestedClaims?: string,
        requestedClaimsHash?: string
    ): AccessTokenEntity {
        const atEntity: AccessTokenEntity = new AccessTokenEntity();

        atEntity.homeAccountId = homeAccountId;
        atEntity.credentialType = CredentialType.ACCESS_TOKEN;
        atEntity.secret = accessToken;

        const currentTime = TimeUtils.nowSeconds();
        atEntity.cachedAt = currentTime.toString();

        /*
         * Token expiry time.
         * This value should be  calculated based on the current UTC time measured locally and the value  expires_in Represented as a string in JSON.
         */
        atEntity.expiresOn = expiresOn.toString();
        atEntity.extendedExpiresOn = extExpiresOn.toString();
        if (refreshOn) {
            atEntity.refreshOn = refreshOn.toString();
        }

        atEntity.environment = environment;
        atEntity.clientId = clientId;
        atEntity.realm = tenantId;
        atEntity.target = scopes;
        atEntity.userAssertionHash = userAssertionHash;

        atEntity.tokenType = StringUtils.isEmpty(tokenType)
            ? AuthenticationScheme.BEARER
            : tokenType;

        if (requestedClaims) {
            atEntity.requestedClaims = requestedClaims;
            atEntity.requestedClaimsHash = requestedClaimsHash;
        }

        /*
         * Create Access Token With Auth Scheme instead of regular access token
         * Cast to lower to handle "bearer" from ADFS
         */
        if (
            atEntity.tokenType?.toLowerCase() !==
            AuthenticationScheme.BEARER.toLowerCase()
        ) {
            atEntity.credentialType =
                CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME;
            switch (atEntity.tokenType) {
                case AuthenticationScheme.POP:
                    // Make sure keyId is present and add it to credential
                    const tokenClaims: TokenClaims | null =
                        AuthToken.extractTokenClaims(accessToken, cryptoUtils);
                    if (!tokenClaims?.cnf?.kid) {
                        throw ClientAuthError.createTokenClaimsRequiredError();
                    }
                    atEntity.keyId = tokenClaims.cnf.kid;
                    break;
                case AuthenticationScheme.SSH:
                    atEntity.keyId = keyId;
            }
        }

        return atEntity;
    }

    /**
     * Validates an entity: checks for all expected params
     * @param entity
     */
    static isAccessTokenEntity(entity: object): boolean {
        if (!entity) {
            return false;
        }

        return (
            entity.hasOwnProperty("homeAccountId") &&
            entity.hasOwnProperty("environment") &&
            entity.hasOwnProperty("credentialType") &&
            entity.hasOwnProperty("realm") &&
            entity.hasOwnProperty("clientId") &&
            entity.hasOwnProperty("secret") &&
            entity.hasOwnProperty("target") &&
            (entity["credentialType"] === CredentialType.ACCESS_TOKEN ||
                entity["credentialType"] ===
                    CredentialType.ACCESS_TOKEN_WITH_AUTH_SCHEME)
        );
    }
}
