declare module "vue" {
  export interface Ref<T> {
    value: T;
  }

  export type ComputedRef<T> = Readonly<Ref<T>>;
  export interface App {
    provide<T>(key: InjectionKey<T> | string | symbol, value: T): void;
  }
  export interface InjectionKey<T> extends Symbol {}

  export function ref<T>(value: T): Ref<T>;
  export function computed<T>(getter: () => T): ComputedRef<T>;
  export function readonly<T>(value: Ref<T>): Readonly<Ref<T>>;
  export function inject<T>(key: InjectionKey<T> | string | symbol): T | undefined;
  export function onUnmounted(cleanup: () => void): void;
}
