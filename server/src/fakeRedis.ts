export type FakeRedisTTL = {
  expirse_in: number;
};

export class FakeRedis {
  private static instance: FakeRedis;
  private data: Map<string, any> = new Map();

  public static getInstance() {
    if (!FakeRedis.instance) FakeRedis.instance = new FakeRedis();
    return FakeRedis.instance;
  }

  public get<T extends FakeRedisTTL>(key: string): T | undefined {
    const payload = this.data.get(key) as T | undefined;
    if (!payload?.expirse_in || payload.expirse_in > (Date.now() / 1000)) this.data.delete(key);
    return payload;
  }

  public set<T extends FakeRedisTTL>(key: string, data: T) {
    this.data.set(key, data);
  }

  public remove(key: string) {
    this.data.delete(key);
  }
}
