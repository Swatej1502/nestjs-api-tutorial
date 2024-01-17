import { ForbiddenException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{
    
    constructor(private prisma:PrismaService,
                private Jwt:JwtService,
                private config:ConfigService){}
    async Signup(dto : AuthDto){
        //generate the password hash
        const hash=await argon.hash(dto.password);
        //save the new user in db
        try{
            const user = await this.prisma.user.create({
                data:{
                    email : dto.email,
                    hash,
                },    
               });
                //return the saved user
             return user;
        }catch(error){
            if(error instanceof  PrismaClientKnownRequestError){
                if( error.code  ==="P2002"){
                    throw new ForbiddenException('Credintials taken');
                }
            }
            throw error;
        }
    
    }
    async signin(dto : AuthDto){
        //find the user
        const user =await this.prisma.user.findUnique({
            where :
             {email: dto.email,
            },
        });
        //if user does not exist throw exception
    if(!user) throw new ForbiddenException(
        'credintials incorrect',
    );

        //compare password
        const pwMatches = await argon.verify(
            user.hash,
            dto.password,
        );
        //if passw incorrect through exception
      if(!pwMatches)
      throw new ForbiddenException(
    'credintials incorrect');

    return this.signToken(user.id,user.email);

    }
     async signToken(
        userId:number,
        email:string,
     ):Promise<{access_token : string}>{
        const payload={
            sub :userId,
            email,
        };
        const secret=this.config.get('JWT_SECRET');

        const token =await this.Jwt.signAsync(payload,{
            expiresIn:'15m',
            secret:secret,
        });

        return{
            access_token : token,
        };

       
     }
}