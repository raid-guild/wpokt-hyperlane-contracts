import { Network } from '@openzeppelin/defender-base-client';
export interface CreateBlockExplorerApiKeyRequest {
    key: string;
    network: Network;
    stackResourceId?: string;
}
export interface UpdateBlockExplorerApiKeyRequest {
    key: string;
    stackResourceId?: string;
}
export interface BlockExplorerApiKeyResponse {
    blockExplorerApiKeyId: string;
    createdAt: string;
    network: Network;
    stackResourceId?: string;
    keyHash: string;
}
//# sourceMappingURL=block-explorer.d.ts.map