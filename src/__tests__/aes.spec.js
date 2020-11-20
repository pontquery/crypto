import { AES } from '../utils'

describe('AES', () => {
  it('should validate that value is text', () => {
    const value = 'Hello'
    const { valid } = validate(value, { text: true }, { type: 'text' })
    expect(valid).toBe(true)
  })
})
