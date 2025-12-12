using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class renameApartmentCache : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            //migrationBuilder.DropForeignKey(
            //    name: "FK_Bookings_Apartments_ApartmentId",
            //    table: "Bookings");

            //migrationBuilder.DropTable(
            //    name: "Apartments");

            migrationBuilder.RenameTable(
                name: "Apartments",
                newName: "ApartmentCaches");

            //migrationBuilder.CreateTable(
            //    name: "ApartmentCaches",
            //    columns: table => new
            //    {
            //        Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
            //        Address = table.Column<string>(type: "nvarchar(max)", nullable: false),
            //        Title = table.Column<string>(type: "nvarchar(max)", nullable: false),
            //        Price = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
            //        Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
            //        Base64Image = table.Column<string>(type: "nvarchar(max)", nullable: false)
            //    },
            //    constraints: table =>
            //    {
            //        table.PrimaryKey("PK_ApartmentCaches", x => x.Id);
            //    });

            //migrationBuilder.AddForeignKey(
            //    name: "FK_Bookings_ApartmentCaches_ApartmentId",
            //    table: "Bookings",
            //    column: "ApartmentId",
            //    principalTable: "ApartmentCaches",
            //    principalColumn: "Id",
            //    onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameTable(
                name: "ApartmentCaches",
                newName: "Apartments");

            //migrationBuilder.DropForeignKey(
            //    name: "FK_Bookings_ApartmentCaches_ApartmentId",
            //    table: "Bookings");

            //migrationBuilder.DropTable(
            //    name: "ApartmentCaches");

            //migrationBuilder.CreateTable(
            //    name: "Apartments",
            //    columns: table => new
            //    {
            //        Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
            //        Address = table.Column<string>(type: "nvarchar(max)", nullable: false),
            //        Base64Image = table.Column<string>(type: "nvarchar(max)", nullable: false),
            //        Description = table.Column<string>(type: "nvarchar(max)", nullable: true),
            //        Price = table.Column<decimal>(type: "decimal(18,2)", nullable: false),
            //        Title = table.Column<string>(type: "nvarchar(max)", nullable: false)
            //    },
            //    constraints: table =>
            //    {
            //        table.PrimaryKey("PK_Apartments", x => x.Id);
            //    });

            //migrationBuilder.AddForeignKey(
            //    name: "FK_Bookings_Apartments_ApartmentId",
            //    table: "Bookings",
            //    column: "ApartmentId",
            //    principalTable: "Apartments",
            //    principalColumn: "Id",
            //    onDelete: ReferentialAction.Cascade);
        }
    }
}
