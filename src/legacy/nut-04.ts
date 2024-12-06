import type { MintQuoteResponse, SignedMintQuoteResponse } from '../model/types/index.js';
import { MintQuoteState } from '../model/types/index.js';

export type MintQuoteResponsePaidDeprecated = {
	paid?: boolean;
};

export function handleMintQuoteResponseDeprecated(
	response: MintQuoteResponse & { pubkey: string }
): SignedMintQuoteResponse;
export function handleMintQuoteResponseDeprecated(response: MintQuoteResponse): MintQuoteResponse;
export function handleMintQuoteResponseDeprecated(
	response: MintQuoteResponse & { paid?: boolean; pubkey?: string }
) {
	// if the response MeltQuoteResponse has a "paid" flag, we monkey patch it to the state enum
	if (!response.state) {
		console.warn(
			"Field 'state' not found in MintQuoteResponse. Update NUT-04 of mint: https://github.com/cashubtc/nuts/pull/141)"
		);
		if (typeof response.paid === 'boolean') {
			(response as MintQuoteResponse).state = response.paid
				? MintQuoteState.PAID
				: MintQuoteState.UNPAID;
		}
	}
	if ('pubkey' in response && typeof response.pubkey === 'string') {
		return response as SignedMintQuoteResponse;
	}
	return response as MintQuoteResponse;
}
