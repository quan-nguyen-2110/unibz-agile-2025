export interface Apartment {
  id: string;
  title: string;
  address: string;
  price: number;
  bedrooms: number;
  bathrooms: number;
  area: number;
  floor: number;
  description: string;
  base64Images: string[];
  availableFrom?: Date;
  amenities: string;
  noisy: NoisyLevel;

  code?: string;
}

export type NoisyLevel = "quiet" | "moderate" | "noisy";