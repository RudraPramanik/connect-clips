import { Field, ObjectType } from '@nestjs/graphql';

@ObjectType()
export class user {
  @Field()
  id?: number;

  @Field()
  fullname: string;

  @Field()
  email?: string;

  @Field({ nullable: true })
  bio: string;

  @Field()
  image: string;

  @Field()
  password: string;

  @Field()
  createdAt: Date;

  @Field()
  updatedAt: Date;
}
