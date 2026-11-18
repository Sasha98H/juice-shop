/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { trackOrder } from '../../routes/trackOrder'
import * as db from '../../data/mongodb'
import config from 'config'
import { challenges } from '../../data/datacache'

void describe('trackOrder literal lookup', () => {
  const originalChallenge = challenges.reflectedXssChallenge
  const getConfig = config.get.bind(config)
  const orderId = '5267-f9cd5882f54c75a3'

  beforeEach(async () => {
    await db.ordersCollection.remove({})
    await db.ordersCollection.insert({ orderId, email: 'customer@example.invalid' })
    await db.ordersCollection.insert({ orderId: 'other-order', email: 'other@example.invalid' })
  })

  afterEach(async () => {
    mock.restoreAll()
    challenges.reflectedXssChallenge = originalChallenge
    await db.ordersCollection.remove({})
    delete (globalThis as any).__trackOrderProbe
  })

  const lookup = async (id: string): Promise<any> => await new Promise((resolve, reject) => {
    const res: any = { json: resolve, status: () => ({ json: reject }) }
    trackOrder()({ params: { id } } as any, res)
  })

  for (const enabled of [true, false]) {
    void describe(`with reflected XSS challenge enabled=${enabled}`, () => {
      beforeEach(() => {
        challenges.reflectedXssChallenge = { disabledEnv: ['Docker'], solved: true } as any
        mock.method(config, 'get', (key: string) => key === 'challenges.safetyMode' ? (enabled ? 'disabled' : 'enabled') : getConfig(key))
      })

      void it('returns only the matching order', async () => {
        const result = await lookup(orderId)
        assert.equal(result.data.length, 1)
        assert.equal(result.data[0].orderId, orderId)
        assert.equal(result.data[0].email, 'customer@example.invalid')
      })

      void it('preserves the unknown identifier response', async () => {
        assert.deepEqual((await lookup('unknown-order')).data, [{ orderId: 'unknown-order' }])
      })

      for (const payload of ["' || true || '", "' || (global.__trackOrderProbe=1) || '", "'", '{"$ne":null}']) {
        void it(`treats ${JSON.stringify(payload)} as data`, async () => {
          const expectedId = enabled ? payload : payload.replace(/[^\w-]+/g, '')
          assert.deepEqual((await lookup(payload)).data, [{ orderId: expectedId }])
          assert.equal((globalThis as any).__trackOrderProbe, undefined)
        })
      }
    })
  }
})
