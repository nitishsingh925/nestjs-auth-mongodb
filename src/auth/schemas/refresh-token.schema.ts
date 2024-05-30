import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose from 'mongoose';

@Schema({ versionKey: false, timestamps: true })
export class RefreshToken extends mongoose.Document {
  @Prop({ required: true })
  token: string;

  @Prop()
  userId: mongoose.Types.ObjectId;

  @Prop({ required: true })
  expiryDate: Date;
}

export const RefreshTokenSchema = SchemaFactory.createForClass(RefreshToken);
