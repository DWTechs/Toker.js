
export type Type = "access" | "refresh";

export type Header = {
  alg: string,
  typ: string,
  kid: number,
};

export type Payload = {
  iss: number | string,
  iat: number,
  nbf: number,
  exp: number,
  typ: Type,
}