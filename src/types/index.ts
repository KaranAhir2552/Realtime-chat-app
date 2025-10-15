export interface IUser {
    email: string;
    password: string;
    username: string;
    isVerified: boolean;
    verificationToken?: string;
}

export interface JwtPayload {
    userId: string;
}