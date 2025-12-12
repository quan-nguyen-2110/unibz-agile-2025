using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class UpdateApartments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Amenities",
                table: "Apartments",
                type: "nvarchar(max)",
                nullable: true,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "AvailableFrom",
                table: "Apartments",
                type: "datetime2",
                nullable: false,
                defaultValue: DateTime.Now);

            migrationBuilder.AddColumn<int>(
                name: "Bathrooms",
                table: "Apartments",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "Bedrooms",
                table: "Apartments",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Description",
                table: "Apartments",
                type: "nvarchar(max)",
                nullable: true,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Images",
                table: "Apartments",
                type: "nvarchar(max)",
                nullable: true,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Title",
                table: "Apartments",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "Title");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Amenities",
                table: "Apartments");

            migrationBuilder.DropColumn(
                name: "AvailableFrom",
                table: "Apartments");

            migrationBuilder.DropColumn(
                name: "Bathrooms",
                table: "Apartments");

            migrationBuilder.DropColumn(
                name: "Bedrooms",
                table: "Apartments");

            migrationBuilder.DropColumn(
                name: "Description",
                table: "Apartments");

            migrationBuilder.DropColumn(
                name: "Images",
                table: "Apartments");

            migrationBuilder.DropColumn(
                name: "Title",
                table: "Apartments");
        }
    }
}
