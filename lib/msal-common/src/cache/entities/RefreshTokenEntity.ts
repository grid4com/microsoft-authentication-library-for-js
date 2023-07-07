/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { CredentialEntity } from "./CredentialEntity";
import { CredentialType } from "../../utils/Constants";

/**
 * REFRESH_TOKEN Cache
 *
 * Key Example: uid.utid-login.microsoftonline.com-refreshtoken-clientId--
 */
export class RefreshTokenEntity extends CredentialEntity {
    /** Family ID identifier, '1' represents Microsoft Family */
    familyId?: string;

    /**
     * Create RefreshTokenEntity
     * @param homeAccountId
     * @param authenticationResult
     * @param clientId
     * @param authority
     */
    static createRefreshTokenEntity(
        homeAccountId: string,
        environment: string,
        refreshToken: string,
        clientId: string,
        familyId?: string,
        userAssertionHash?: string
    ): RefreshTokenEntity {
        const rtEntity = new RefreshTokenEntity();

        rtEntity.clientId = clientId;
        rtEntity.credentialType = CredentialType.REFRESH_TOKEN;
        rtEntity.environment = environment;
        rtEntity.homeAccountId = homeAccountId;
        rtEntity.secret = refreshToken;
        rtEntity.userAssertionHash = userAssertionHash;

        if (familyId) rtEntity.familyId = familyId;

        return rtEntity;
    }

    /**
     * Validates an entity: checks for all expected params
     * @param entity
     */
    static isRefreshTokenEntity(entity: object): boolean {
        if (!entity) {
            return false;
        }

        return (
            entity.hasOwnProperty("homeAccountId") &&
            entity.hasOwnProperty("environment") &&
            entity.hasOwnProperty("credentialType") &&
            entity.hasOwnProperty("clientId") &&
            entity.hasOwnProperty("secret") &&
            entity["credentialType"] === CredentialType.REFRESH_TOKEN
        );
    }
}
