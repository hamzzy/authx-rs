declare module "react" {
  export type ReactNode = unknown;

  export interface ProviderProps<T> {
    value: T;
    children?: ReactNode;
  }

  export interface Context<T> {
    Provider: (props: ProviderProps<T>) => unknown;
  }

  export function createContext<T>(defaultValue: T): Context<T>;
  export function createElement(
    type: unknown,
    props?: Record<string, unknown> | null,
    ...children: unknown[]
  ): unknown;
  export function useContext<T>(context: Context<T>): T;
  export function useEffect(
    effect: () => void | (() => void),
    deps?: readonly unknown[],
  ): void;
  export function useState<T>(
    initialState: T | (() => T),
  ): [T, (value: T | ((previous: T) => T)) => void];
}
