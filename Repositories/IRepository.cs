using System.Linq.Expressions;
namespace QuizArena.Repositories;
public interface IRepository<T> where T : class
{
    Task<T?> GetByIdAsync(object id);
    Task<IEnumerable<T>> ListAsync();
    Task AddAsync(T entity);
    void Update(T entity);
    void Remove(T entity);
}
