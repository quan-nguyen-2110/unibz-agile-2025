using Application.Apartments.Commands;
using Application.Apartments.Queries;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace Api.Controllers;

/// <summary>
/// Manages apartments in the system.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class ApartmentController(IMediator mediator) : ControllerBase
{
    /// <summary>
    /// Get a list of all apartments.
    /// </summary>
    /// <remarks>
    /// This endpoint returns all apartments stored in the database.
    /// </remarks>
    /// <response code="200">Returns the list of apartments</response>
    /// <response code="500">Server error</response>
    /// <returns></returns>
    [HttpGet]
    public async Task<IActionResult> GetAll()
        => Ok(await mediator.Send(new GetAllApartmentsQuery()));

    /// TO-DO: Filter API
    ///

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(Guid id)
        => Ok(await mediator.Send(new GetApartmentByIdQuery(id)));

    /// <summary>
    /// Initiates the creation of a new apartment using the specified command.
    /// </summary>
    /// <remarks>
    /// Create a new apartment
    /// </remarks>
    /// <param name="cmd">The command containing the details required to create the apartment.</param>
    /// <returns>An <see cref="IActionResult"/> indicating the result of the operation.</returns>
    [HttpPost]
    public async Task<IActionResult> Create(CreateApartmentCommand cmd)
        => Ok(await mediator.Send(cmd));

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(Guid id, UpdateApartmentCommand cmd)
    {
        if (id != cmd.Id) return BadRequest("ID mismatch");
        await mediator.Send(cmd);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        await mediator.Send(new DeleteApartmentCommand(id));
        return NoContent();
    }
}
